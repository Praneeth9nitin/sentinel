use aya::{maps::RingBuf , programs::TracePoint};
mod helpers;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::{io::unix::AsyncFd, signal};


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

    let ring = RingBuf::try_from(ebpf.take_map("EVENTS").expect("EVENTS maps not found"))?;
    let mut async_ring = AsyncFd::new(ring)?;

    let program: &mut TracePoint = ebpf.program_mut("sentinel").unwrap().try_into()?;
    program.load()?;
    program.attach("syscalls", "sys_enter_execve")?;
    program.attach("syscalls",  "sys_enter_openat")?;
    program.attach("syscalls",  "sys_enter_connect")?;

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
                println!("{kind}");
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

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
