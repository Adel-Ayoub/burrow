<div align="center">

# Burrow

**A minimal, zero-dependency SSH 2.0 client library and terminal for Zig**

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Zig](https://img.shields.io/badge/zig-0.14.0-orange.svg)](https://ziglang.org)

</div>

## Features

- **SSH 2.0 Protocol**: Full handshake, key exchange, encryption, and MAC verification
- **Key Exchange**: curve25519-sha256 (ECDH with X25519)
- **Host Key**: ssh-ed25519 with signature verification
- **Encryption**: AES-256-CTR with HMAC-SHA2-256
- **Password Auth**: Standard password-based authentication
- **Ed25519 Auth**: Public key authentication with Ed25519 keypairs
- **Command Execution**: Run remote commands and collect stdout/stderr
- **Interactive Shell**: PTY allocation with raw terminal mode
- **Key Generation**: Generate Ed25519 keypairs and OpenSSH public key export
- **Zero Dependencies**: Everything from Zig's `std.crypto` — no external packages
- **Terminal UI**: Built-in interactive SSH client with `poll()`-based I/O

## Architecture

Burrow is a single Zig package with a library and a CLI executable:

| File | Role |
|------|------|
| `connection.zig` | SSH handshake, key exchange, authentication |
| `packets.zig` | Encrypted packet framing (read/write with MAC) |
| `cipher.zig` | Stateful AES-256-CTR stream cipher |
| `hmac.zig` | HMAC-SHA256 with cloneable state |
| `messages.zig` | SSH message types and encoding |
| `channel_request.zig` | Channel requests (exec, pty-req, shell, window-change) |
| `user_auth.zig` | User authentication request encoding and signing |
| `run.zig` | Command execution, shell sessions, channel I/O |
| `wire.zig` | SSH binary wire format primitives |
| `keygen.zig` | Ed25519 key generation and OpenSSH export |
| `main.zig` | Interactive terminal SSH client |
| `root.zig` | Library root with public API |

## Installation

### From Source

```bash
git clone https://github.com/Adel-Ayoub/burrow
cd burrow
zig build -Doptimize=ReleaseFast
```

Binary is produced at `zig-out/bin/burrow`.

### As a Zig Package

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .burrow = .{
        .url = "https://github.com/Adel-Ayoub/burrow/archive/refs/heads/main.tar.gz",
    },
},
```

Then in your `build.zig`:

```zig
const burrow = b.dependency("burrow", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("burrow", burrow.module("burrow"));
```

## Quick Start

### Interactive Shell

```bash
# Password authentication
burrow user@hostname

# Ed25519 key authentication
burrow -i ~/.ssh/key.hex user@hostname

# Custom port
burrow -p 2222 user@hostname
```

### As a Library

```zig
const burrow = @import("burrow");
const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    // Connect
    const stream = try std.net.tcpConnectToHost(allocator, "example.com", 22);
    var conn = try burrow.connect(allocator, stream, .{ .password = .{
        .username = "user",
        .password = "secret",
    }});
    defer conn.deinit();

    // Run a command
    if (try conn.quickRun(allocator, "uname -a")) |result| {
        defer allocator.free(result.output);
        std.debug.print("{s}\n", .{result.output});
    }
}
```

### Key Generation

```zig
const burrow = @import("burrow");

// Generate a new Ed25519 keypair (128-char hex string)
const hex_keypair = try burrow.createEd25519Keypair(allocator);
defer allocator.free(hex_keypair);

// Export as OpenSSH authorized_keys line
const pubkey = try burrow.dumpEd25519PkOpenssh(allocator, hex_keypair, "user@host");
defer allocator.free(pubkey);
```

## Usage

```
Usage: burrow [options] [user@]host

Options:
  -p PORT     Port (default: 22)
  -i KEYFILE  Ed25519 hex keypair file
```

If no `-i` is provided, burrow prompts for a password with echo disabled.

## Project Structure

```
burrow/
├── build.zig           # Build configuration (library + executable)
├── build.zig.zon       # Package manifest
├── LICENSE
├── README.md
└── src/
    ├── main.zig            # Interactive terminal SSH client
    ├── root.zig            # Library root, public API
    ├── connection.zig      # Handshake, key exchange, auth
    ├── run.zig             # Command execution, shell sessions
    ├── packets.zig         # Encrypted packet framing
    ├── messages.zig        # SSH message types
    ├── channel_request.zig # Channel requests (exec, pty, shell)
    ├── user_auth.zig       # Authentication encoding + signing
    ├── wire.zig            # Binary wire format primitives
    ├── cipher.zig          # AES-256-CTR stream cipher
    ├── hmac.zig            # HMAC-SHA256
    └── keygen.zig          # Ed25519 key generation
```

## License

MIT License — Copyright (c) 2026 Adel-Ayoub. See [LICENSE](LICENSE) for details.
