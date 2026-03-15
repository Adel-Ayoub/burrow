const std = @import("std");
const wire = @import("wire.zig");
const messages = @import("messages.zig");

pub const UserauthRequest = union(enum) {
    PublicKey: struct {
        username: []const u8,
        service_name: []const u8,
        algorithm: []const u8,
        blob: messages.Blob,
        signature: ?messages.Blob,
    },
    Password: struct {
        username: []const u8,
        service_name: []const u8,
        password: []const u8,
        new_password: ?[]const u8,
    },

    pub fn write(self: UserauthRequest, buf: *std.ArrayList(u8)) !void {
        try wire.writeU8(buf, @intFromEnum(messages.MessageType.UserauthRequest));
        switch (self) {
            .PublicKey => |pk| {
                try wire.writeStr(buf, pk.username);
                try wire.writeStr(buf, pk.service_name);
                try wire.writeStr(buf, "publickey");
                try wire.writeBool(buf, pk.signature != null);
                try wire.writeStr(buf, pk.algorithm);
                try pk.blob.write(buf);
                if (pk.signature) |sig| try sig.write(buf);
            },
            .Password => |pw| {
                try wire.writeStr(buf, pw.username);
                try wire.writeStr(buf, pw.service_name);
                try wire.writeStr(buf, "password");
                try wire.writeBool(buf, pw.new_password != null);
                try wire.writeStr(buf, pw.password);
                if (pw.new_password) |np| try wire.writeStr(buf, np);
            },
        }
    }
};

/// Signs the userauth data for a public-key auth request.
/// Returns the 64-byte Ed25519 signature.
pub fn signUserauth(
    kp: std.crypto.sign.Ed25519.KeyPair,
    session_id: []const u8,
    username: []const u8,
    service_name: []const u8,
    pub_blob: messages.Blob,
    allocator: std.mem.Allocator,
) ![64]u8 {
    var msg = std.ArrayList(u8).init(allocator);
    defer msg.deinit();

    try wire.writeBytes(&msg, session_id);
    try wire.writeU8(&msg, @intFromEnum(messages.MessageType.UserauthRequest));
    try wire.writeStr(&msg, username);
    try wire.writeStr(&msg, service_name);
    try wire.writeStr(&msg, "publickey");
    try wire.writeBool(&msg, true);
    try wire.writeStr(&msg, "ssh-ed25519");
    try pub_blob.write(&msg);

    const sig = try kp.sign(msg.items, null);
    return sig.toBytes();
}
