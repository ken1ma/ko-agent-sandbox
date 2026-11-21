# Design decisions on Windows

The standing decisions that only Windows hosts motivate. `design.md`, "Standing design
decisions", says what a standing decision fixes and what reopens one.

## Standing design decisions

### Machine scripts go through `podman machine ssh`, not `wsl.exe`

A cold `podman machine ssh` takes 0.7 to 1.1s under podman's WSL provider, while
`wsl.exe -d <machine> -u <user>` runs a command in 0.15s. The launcher still runs every machine
script through `podman machine ssh` (`KoAgentFs.koAgentFsScriptCommand`). wsl.exe's commands run
outside the machine's login session, whose podman store and systemd user manager the scripts use.
Measured on the machine `podman-machine-default` (2026-11-21):

- Under wsl.exe, `XDG_RUNTIME_DIR` names WSLg's runtime directory, and
  `DBUS_SESSION_BUS_ADDRESS` is unset.
- `systemctl --user` fails with "Transport endpoint is not connected", even with
  `XDG_RUNTIME_DIR` set to the session's `/run/user/<uid>`.
- A podman started under wsl.exe, with the session's `XDG_RUNTIME_DIR`, judged the live pause
  process of the session's podman not to be one, and removed its `pause.pid`.
- A machine under podman's Hyper-V provider has no WSL distribution.

What serves instead: `KoAgentFs.MachineShell` starts the connections of the BPF backend's
reconcile and of the first machine script after the start prompt ahead of their scripts. The
BPF backend's launch script then spends 0.11 to 0.23s outside its steps in the machine.

### The launcher's text is ASCII

Every string in the launcher's sources is ASCII, except characters it matches or writes into a
script. `AsciiTextTest` enforces this and lists those characters. A Windows host shows any other
character wrong wherever the text goes. Some of that text is consent or refusal text, which a
reader must be able to trust verbatim. Measured on Japanese Windows (Windows Server 2025):

- In Windows Terminal, Java writes `System.out` in the console's code page, 932: `—`, which code
  page 932 lacks, prints as `?`.
- Redirected to a file, Java writes in the system's code page (`native.encoding`, MS932), while
  podman's lines in the same file are UTF-8.
- Written as UTF-8, `→—` shows in Windows Terminal as `竊停・`.

ASCII is the same bytes in every one of these encodings. The launcher prints text it passes along
as it is, such as a path with a non-ASCII name or podman's own lines.

Revisit if Windows consoles default to code page 65001 (UTF-8), or if the launcher sets the
console's code page itself (`SetConsoleOutputCP`). Every process attached to that console would
then share that code page.

