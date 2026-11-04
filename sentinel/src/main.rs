use aya::{programs::TracePoint,  maps::{HashMap as BpfHashMap, RingBuf}};
use std::{ffi::CString, os::fd::AsRawFd, time::Duration};
use anyhow::Context;
mod helpers;
#[rustfmt::skip]
use log::{debug};
use tokio::{io::unix::AsyncFd, signal};
use clap::Parser;
use nix::{
    sys::wait::waitpid,
    unistd::{fork, pipe, ForkResult},
};


#[derive(Parser)]
struct Sentinel {
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    
    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/sentinel"
    )))?;

    let mut tracked: BpfHashMap<_, u32, u8> =
    BpfHashMap::try_from(ebpf.take_map("TRACKED").context("no TRACKED")?)?;
    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").expect("EVENTS maps not found"))?;

    let args = Sentinel::parse();
    let argv: Vec<CString> = args
        .command
        .iter()
        .map(|s| CString::new(s.as_str()))
        .collect::<Result<_, _>>()
        .context("command contains a NUL byte")?;
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|c| c.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());

    attach_tp(&mut ebpf, "sys_enter_execve", "syscalls", "sys_enter_execve")?;
    attach_tp(&mut ebpf, "sys_enter_openat", "syscalls", "sys_enter_openat")?;
    attach_tp(&mut ebpf, "sys_enter_connect", "syscalls", "sys_enter_connect")?;
    attach_tp(&mut ebpf, "sched_fork", "sched", "sched_process_fork")?;
    attach_tp(&mut ebpf, "sched_exit", "sched", "sched_process_exit")?;

    let (read_fd, write_fd) = pipe()?;
    match unsafe { fork() } {
        Ok(ForkResult::Child) => {
             unsafe {
                libc::close(write_fd.as_raw_fd());
                let mut buf = [0u8; 1];
                libc::read(read_fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, 1);
                libc::close(read_fd.as_raw_fd());
                libc::execvp(argv_ptrs[0], argv_ptrs.as_ptr());
                libc::_exit(127);
            }
        }
        Ok(ForkResult::Parent { child }) => {
            drop(read_fd);

            tracked.insert(child.as_raw() as u32, 1, 0)?;
            let mut async_ring = AsyncFd::new(ring)?;
            tokio::spawn(async move {
                loop {
                    let mut guard = match async_ring.readable_mut().await{
                        Ok(g) => g,
                        Err(e) => {
                            eprint!("ringbuffer error: {e}");
                            break;
                        }
                    };
                    let ring = guard.get_inner_mut();
                    while let Some(item) = ring.next() {
                        if item.len() < core::mem::size_of::<u32>() {
                            continue;
                        }
                        let kind = u32::from_ne_bytes([item[0], item[1], item[2], item[3]]);
                        match kind{
                            1 => helpers::execve_tracing(&item),
                            2 => helpers::openat_tracing(&item),
                            3 => helpers::connect_tracing(&item),
                            _ => {}
                        }
                    }
                    guard.clear_ready();
                }
            });

            drop(write_fd);

            println!("Watching pid {} ({}). Ctrl-C to stop.", child, args.command.join(" "));

            let child_exit = tokio::task::spawn_blocking(move || waitpid(child, None));
            tokio::select! {
                _ = child_exit => {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    println!("Monitored process exited.");
                }
                _ = signal::ctrl_c() => {
                    println!("Exiting...");
                }
            }
        }
        Err(e) => {
            return Err(anyhow::anyhow!("Fork failed: {}", e));
        }
    }


    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}

fn attach_tp(ebpf: &mut aya::Ebpf, prog: &str, category: &str, name: &str) -> anyhow::Result<()> {
    let p: &mut TracePoint = ebpf
        .program_mut(prog)
        .with_context(|| format!("program {prog} not found"))?
        .try_into()?;
    p.load()?;
    p.attach(category, name)?;
    Ok(())
}
