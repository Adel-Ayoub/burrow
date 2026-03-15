/// burrow — SSH 2.0 client library for Zig.
///
/// Algorithms:
///   kex:         curve25519-sha256
///   host key:    ssh-ed25519
///   cipher:      aes256-ctr
///   mac:         hmac-sha2-256
///   compression: none
///
/// Auth:          password, ed25519 public-key
///
/// No external dependencies — everything comes from `std.crypto`.
pub const connection = @import("connection.zig");
pub const run = @import("run.zig");
pub const messages = @import("messages.zig");
pub const keygen = @import("keygen.zig");
pub const wire = @import("wire.zig");
pub const cipher = @import("cipher.zig");
pub const hmac = @import("hmac.zig");
pub const packets = @import("packets.zig");
pub const channel_request = @import("channel_request.zig");
pub const user_auth = @import("user_auth.zig");

pub const Connection = connection.Connection;
pub const Auth = connection.Auth;
pub const Run = run.Run;
pub const RunResult = run.RunResult;
pub const RunEvent = run.RunEvent;
pub const ExitStatus = run.ExitStatus;
pub const MessageType = messages.MessageType;

pub const createEd25519Keypair = keygen.createEd25519Keypair;
pub const dumpEd25519PkOpenssh = keygen.dumpEd25519PkOpenssh;

/// Open an SSH connection and authenticate over an existing TCP stream.
pub const connect = Connection.init;

/// Connect to a TCP address, then SSH-handshake + authenticate.
pub const connectTcp = Connection.connectTcp;

/// Run a command on an authenticated connection.
pub const runCommand = run.runCommand;

test {
    @import("std").testing.refAllDecls(@This());
}
