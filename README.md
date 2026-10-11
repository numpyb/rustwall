# ufw-manager

A centralized UFW (Uncomplicated Firewall) management tool built in Rust. Manage your localhost and remote hosts' UFW firewall rules over SSH through an intuitive GUI—no need to juggle multiple interfaces or terminals.

## Features

- Centralized control for localhost and remote machines
- Secure SSH-based remote management
- Simple, focused GUI for UFW tasks
- Manage hosts and firewall rules from one place
- Built for Linux systems using UFW

## Why this app exists

I wanted a lightweight alternative to large admin tools like Cockpit when I just needed a fast, focused way to manage UFW across multiple systems. There was no tool that fit my use case cleanly: a central control point for localhost and remote hosts without the overhead of bigger web dashboards.

ufw-manager is designed for that workflow: manage firewall settings centrally and remotely over SSH.

## Requirements

Before using ufw-manager, make sure you have:

- Rust installed (for building from source)
- UFW installed on the machine you want to manage
- SSH access to remote hosts if you plan to manage them
- Appropriate sudo privileges to run firewall commands

## Install

### Option 1: Build from source

1. Clone the repository:

   ```bash
   git clone https://github.com/numpyb/ufw-manager.git
   cd ufw-manager
   ```

2. Build the app:

   ```bash
   cargo build --release
   ```

3. Run it:

   ```bash
   ./target/release/ufw-manager
   ```

### Option 2: Download a release binary

Visit the GitHub Releases page and download the binary for your platform, then run it directly.

## Quick start

1. Launch ufw-manager.
2. Add a host entry for either:
   - your local machine
   - a remote system reachable over SSH
3. Connect using SSH credentials or key-based authentication.
4. View the current UFW state.
5. Add, remove, or manage firewall rules for that host.

## Remote host setup

To manage a remote machine, make sure:

- SSH is enabled and reachable
- The target host has UFW installed
- Your user can run UFW-related commands with sudo
- SSH keys are configured if you want passwordless access

Example connection flow:

```bash
ssh user@remote-host
sudo ufw status
```

## Typical usage

This app is especially useful when you want to:

- manage a local firewall from one place
- manage several remote machines over SSH
- keep a simple, focused interface instead of a larger admin suite
- work with UFW without needing a full web-based management stack

## Development

```bash
cargo build
cargo run
```

## Notes

This project is currently a focused UFW management utility for Linux environments. It is best suited for users who want a simple central point of control for local and remote firewall administration.

## License

See the LICENSE file if present in the repository.
