# sentinel

**Kernel-level policy alerts for AI agents.** Run your agent under `sentinel`, give it a policy, and get a real-time alert the moment it opens a file, starts a program, or connects to a host that the policy doesn't allow.

Built with Rust and eBPF ([Aya](https://aya-rs.dev)). Linux only. **Early version (v0.1): alert-only.**

<!-- Put the 60-second demo recording (GIF or video) here. This is the most important line in the file. -->
https://github.com/user-attachments/assets/0f77660e-d105-42aa-a43a-3feed19de820

## Why

AI agents are being given real access: files, shells, the network. Prompt-level defenses can be tricked, so a hijacked agent may still read a secret and send it out.

`sentinel` doesn't read prompts. It watches what the agent process **actually does** at the kernel level, so it can't be talked out of what it sees. If an injected instruction makes your support bot open `/etc/shadow` or call an unknown host, you get an alert naming the exact action.

## What it does today

- Launches a command and follows **every child process** it spawns
- Reports `execve`, `openat`, and `connect` events straight from the kernel (IPv4 and IPv6 destinations)
- Checks each event against a per-agent **YAML policy** (allowed files, programs, and destinations, plus optional deny rules)
- Prints an alert that says what happened and which rule it broke
- Refuses to start a program that isn't on the policy's program list

## What it does *not* do (yet)

Please read this before relying on it.

- **It does not detect prompt injection.** The kernel can't see prompts. It sees the *effects*: unexpected files, programs, and connections.
- **Alert-only.** Runtime events are reported after the action has happened. The only block today is the pre-launch program check. Kernel-level blocking (BPF LSM) is on the roadmap.
- **It cannot see attacks that stay within allowed behavior.** An agent allowed to email anyone can still be tricked into emailing something harmful.
- **Relative file paths** (such as `.`) can't be judged properly yet.
- **Failed exec attempts** made by the agent's own subprocesses (PATH searches) can appear as extra exec events.
- **Linux servers only.** Needs a recent kernel with BTF and root privileges. Not for macOS, Windows, or platforms that block eBPF. MicroVMs need the agent running inside the guest.
- No GPU visibility, container (cgroup) scoping, or dashboard yet. No overhead benchmark has been published yet.

## Quick start

### Requirements

- Linux (tested on Ubuntu 24.04), kernel 5.15+ with BTF (`ls /sys/kernel/btf/vmlinux`)
- Root access (loading eBPF programs needs it)
- Rust stable and nightly (with `rust-src`), `bpf-linker`

```bash
rustup install stable
rustup toolchain install nightly --component rust-src
cargo install bpf-linker
```

### Build

```bash
git clone https://github.com/<you>/sentinel
cd sentinel
cargo build --release
```

### Run the demo

The demo agent does two allowed things and two forbidden ones.

```bash
# 1. Create the demo files (all fake)
mkdir -p ~/demo/kb ~/demo/secrets
echo "Support hours are 9am to 5pm." > ~/demo/kb/info.txt
echo "FAKE-API-KEY-1234" > ~/demo/secrets/key.txt
cp demo/agent.py demo/policy.yaml ~/demo/

# 2. Start the "approved API" in a second terminal
cd ~/demo && python3 -m http.server 8000 --bind 127.0.0.1

# 3. Run the agent under sentinel
sudo -E target/release/sentinel --policy ~/demo/policy.yaml -- python3 ~/demo/agent.py
```

Expected: the allowed steps are silent, and two kinds of alert appear: one for `secrets/key.txt` and one (or several, since the host resolves to multiple addresses) for the unapproved destination.

Edit the paths in `policy.yaml` if your home directory is not `/home/ubuntu`.

### Usage

```
sentinel [OPTIONS] -- <COMMAND>...

Options:
  --policy <FILE>   Policy file to enforce (required)
  --verbose         Also print allowed events
```

Options go before `--`. Everything after `--` is the command to run and monitor.

## Policy format

One policy per agent. Deny rules win over allow rules.

```yaml
agent: demo-agent

files:
  allow:
    - /home/ubuntu/demo/kb/        # trailing slash = anything inside this folder
    - /home/ubuntu/demo/agent.py   # no slash = exact path
    - /etc/resolv.conf
  deny:
    - /home/ubuntu/demo/secrets/

programs:
  allow:
    - /usr/bin/python3

network:
  allow:
    - 127.0.0.53:53                # local DNS
    - 127.0.0.1:8000               # approved API
```

Matching rules:

- A folder rule must end with `/` and matches whole path components, so `/kb/` does not match `/kb-secrets/`.
- Any path containing `..` is a violation.
- Network rules are `ip:port` (IPv6 as `[addr]:port`).

Writing the allow list by hand is the hard part. A good starting point is to run the agent once with `--verbose` and a permissive policy, then copy what you see into a draft. (An automatic "learn mode" is planned.)

## How it works

```
 your agent (and its children)        Linux kernel                  sentinel (Rust)
┌───────────────────────────┐   ┌──────────────────────────┐   ┌─────────────────────────┐
│ python3 agent.py          │──▶│ tracepoints:             │──▶│ ring buffer reader      │
│  └─ opens, execs,         │   │  execve, openat, connect │   │ policy check per event  │
│     connects              │   │ fork/exit probes keep a  │   │ ALERT / verbose output  │
└───────────────────────────┘   │ map of tracked processes │   └─────────────────────────┘
                                └──────────────────────────┘
```

1. `sentinel` loads its eBPF programs, then forks and starts your command.
2. The child waits until its PID is registered in a kernel map, so nothing it does at startup is missed.
3. Probes drop events from any process not in the map. A fork probe adds children; an exit probe removes finished processes.
4. Events go through a ring buffer to userspace, where each one is checked against the policy.

## Threat model (short version)

| In scope | Out of scope for now |
|---|---|
| A hijacked agent touching files, programs, or hosts outside its policy | Detecting the prompt injection itself |
| Spawning unexpected child programs (shell, curl) | Malicious actions inside allowed behavior |
| An audit trail of what the agent did | A compromised kernel or root attacker who tampers with the sentinel |
| | Blocking (alert-only today) |

## Roadmap

- [x] Process, file, and network events from the kernel
- [x] Scoping to a launched process tree
- [x] YAML policy and alerts
- [ ] Hide failed exec attempts (`sys_exit_execve`)
- [ ] Ring buffer drop counter
- [ ] `--kill-on-alert`
- [ ] Container (cgroup) scoping and Kubernetes DaemonSet
- [ ] Learn mode (suggest a policy from observed behavior)
- [ ] Kernel-level blocking via BPF LSM
- [ ] GPU visibility (CUDA uprobes)
- [ ] Overhead benchmarks

## Contributing and feedback

This is an early project. The most useful thing you can do is **tell me how you run AI agents** (cloud servers, Kubernetes, laptops) and what you'd want it to catch. Open an issue or reach out.

Security issues: please report them privately (see `SECURITY.md` once added).

## License

Dual MIT / Apache-2.0 for userspace code, GPL for the eBPF programs (required by the kernel for some helper functions). Check the `LICENSE-*` files in the repo.