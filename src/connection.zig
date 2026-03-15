const std = @import("std");
const packets = @import("packets.zig");
const messages = @import("messages.zig");
const user_auth = @import("user_auth.zig");
const run_mod = @import("run.zig");
const wire = @import("wire.zig");
const keygen = @import("keygen.zig");
const cipher_mod = @import("cipher.zig");
const hmac_mod = @import("hmac.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
const X25519 = std.crypto.dh.X25519;
const Ed25519 = std.crypto.sign.Ed25519;

pub const VERSION_HEADER = "SSH-2.0-burrow+1.0";

pub const Auth = union(enum) {
    password: struct {
        username: []const u8,
        password: []const u8,
    },
    ed25519: struct {
        username: []const u8,
        /// 128-character hex-encoded keypair (seed || public_key)
        hex_keypair: []const u8,
    },
};

pub const Connection = struct {
    allocator: std.mem.Allocator,
    reader: packets.PacketReader,
    writer: packets.PacketWriter,
    next_client_channel: u32,

    /// Open an SSH connection over an already-established TCP stream.
    /// Performs the full handshake (key exchange + user authentication).
    pub fn init(allocator: std.mem.Allocator, stream: std.net.Stream, auth: Auth) !Connection {
        var reader = packets.PacketReader.init(allocator, stream);
        errdefer reader.deinit();
        var writer = packets.PacketWriter.init(allocator, stream);
        errdefer writer.deinit();

        // ---- Version exchange ----
        try stream.writeAll(VERSION_HEADER ++ "\r\n");

        var line_buf: [512]u8 = undefined;
        const peer_version: []const u8 = blk: {
            while (true) {
                var len: usize = 0;
                while (len < line_buf.len) {
                    const b = try stream.reader().readByte();
                    line_buf[len] = b;
                    len += 1;
                    if (b == '\n') break;
                }
                const line = line_buf[0..len];
                if (std.mem.startsWith(u8, line, "SSH-2.0-") or
                    std.mem.startsWith(u8, line, "SSH-1.99-"))
                {
                    var end = line.len;
                    if (end > 0 and line[end - 1] == '\n') end -= 1;
                    if (end > 0 and line[end - 1] == '\r') end -= 1;
                    break :blk line[0..end];
                }
            }
        };

        // ---- Algorithm negotiation (KEXINIT) ----
        const client_kexinit = messages.Kexinit{
            .cookie = [_]u8{0} ** 16,
            .kex_algorithms = "curve25519-sha256",
            .server_host_key_algorithms = "ssh-ed25519",
            .encryption_algorithms_client_to_server = "aes256-ctr",
            .encryption_algorithms_server_to_client = "aes256-ctr",
            .mac_algorithms_client_to_server = "hmac-sha2-256",
            .mac_algorithms_server_to_client = "hmac-sha2-256",
            .compression_algorithms_client_to_server = "none",
            .compression_algorithms_server_to_client = "none",
            .languages_client_to_server = "",
            .languages_server_to_client = "",
            .first_kex_packet_follows = false,
            .nop = 0,
        };

        var client_kexinit_payload = std.ArrayList(u8).init(allocator);
        defer client_kexinit_payload.deinit();
        try client_kexinit.write(&client_kexinit_payload);
        try writer.sendRaw(client_kexinit_payload.items);

        const server_kexinit_payload = try reader.recvRaw();
        var ski_r = wire.Reader.init(server_kexinit_payload[1..]);
        const server_kexinit = try messages.Kexinit.parse(&ski_r);
        try server_kexinit.checkCompat(client_kexinit);

        // ---- Key exchange (curve25519-sha256) ----
        var seed: [32]u8 = undefined;
        std.crypto.random.bytes(&seed);
        const ephemeral_kp = try X25519.KeyPair.generateDeterministic(seed);
        const client_pub = ephemeral_kp.public_key;

        {
            var kexdh_buf = std.ArrayList(u8).init(allocator);
            defer kexdh_buf.deinit();
            try (messages.KexdhInit{ .client_ephemeral_pubkey = &client_pub }).write(&kexdh_buf);
            try writer.sendRaw(kexdh_buf.items);
        }

        const reply_payload = try reader.recvRaw();
        if (reply_payload.len == 0 or
            try messages.MessageType.fromByte(reply_payload[0]) != .KexdhReply)
            return error.UnexpectedMessageType;

        var r = wire.Reader.init(reply_payload[1..]);
        const kexdh_reply = try messages.KexdhReply.parse(&r);

        if (kexdh_reply.server_ephemeral_pubkey.len != 32 or
            kexdh_reply.exchange_hash_signature.content.len != 64 or
            kexdh_reply.server_public_host_key.content.len != 32)
            return error.InvalidData;

        var sep: [32]u8 = undefined;
        @memcpy(&sep, kexdh_reply.server_ephemeral_pubkey);
        const shared_secret_bytes = try X25519.scalarmult(ephemeral_kp.secret_key, sep);

        // ---- Exchange hash & host key verification ----
        var exchange_hash: [32]u8 = undefined;
        {
            var h_buf = std.ArrayList(u8).init(allocator);
            defer h_buf.deinit();
            try wire.writeBytes(&h_buf, VERSION_HEADER);
            try wire.writeBytes(&h_buf, peer_version);
            try wire.writeBytes(&h_buf, client_kexinit_payload.items);
            try wire.writeBytes(&h_buf, server_kexinit_payload);
            try kexdh_reply.server_public_host_key.write(&h_buf);
            try wire.writeBytes(&h_buf, &client_pub);
            try wire.writeBytes(&h_buf, kexdh_reply.server_ephemeral_pubkey);
            try wire.writeMpInt(&h_buf, &shared_secret_bytes);
            var hasher = Sha256.init(.{});
            hasher.update(h_buf.items);
            hasher.final(&exchange_hash);
        }

        const host_pub = try Ed25519.PublicKey.fromBytes(
            kexdh_reply.server_public_host_key.content[0..32].*,
        );
        var sig_bytes: [64]u8 = undefined;
        @memcpy(&sig_bytes, kexdh_reply.exchange_hash_signature.content[0..64]);
        try Ed25519.Signature.fromBytes(sig_bytes).verify(&exchange_hash, host_pub);

        // ---- NEWKEYS ----
        const newkeys_payload = [_]u8{@intFromEnum(messages.MessageType.Newkeys)};
        try writer.sendRaw(&newkeys_payload);
        _ = try reader.recvRaw(); // server's Newkeys

        // ---- Key derivation ----
        const session_id = exchange_hash;
        const kex_out = try deriveKeys(allocator, &shared_secret_bytes, &exchange_hash, &session_id);

        writer.setEncryptor(
            cipher_mod.Aes256Ctr64Be.init(kex_out.c2s_key, kex_out.c2s_iv),
            hmac_mod.Hmac.init(&kex_out.c2s_hmac),
            32,
        );
        reader.setDecryptor(
            cipher_mod.Aes256Ctr64Be.init(kex_out.s2c_key, kex_out.s2c_iv),
            hmac_mod.Hmac.init(&kex_out.s2c_hmac),
            32,
            32,
        );

        // ---- Service request: ssh-userauth ----
        {
            var buf = std.ArrayList(u8).init(allocator);
            defer buf.deinit();
            try (messages.ServiceRequest{ .service_name = "ssh-userauth" }).write(&buf);
            try writer.sendRaw(buf.items);
        }
        _ = try reader.recv(.ServiceAccept);

        // ---- User authentication ----
        const service_name = "ssh-connection";
        switch (auth) {
            .password => |pw| {
                var buf = std.ArrayList(u8).init(allocator);
                defer buf.deinit();
                try (user_auth.UserauthRequest{ .Password = .{
                    .username = pw.username,
                    .service_name = service_name,
                    .password = pw.password,
                    .new_password = null,
                } }).write(&buf);
                try writer.sendRaw(buf.items);
            },

            .ed25519 => |ek| {
                const raw = keygen.decodeHex(64, ek.hex_keypair) orelse return error.InvalidKeypair;
                const kp = try Ed25519.KeyPair.generateDeterministic(raw[0..32].*);
                const pub_blob = messages.Blob{ .header = "ssh-ed25519", .content = &kp.public_key.toBytes() };

                // Probe: confirm server accepts this key before signing.
                {
                    var buf = std.ArrayList(u8).init(allocator);
                    defer buf.deinit();
                    try (user_auth.UserauthRequest{ .PublicKey = .{
                        .username = ek.username,
                        .service_name = service_name,
                        .algorithm = "ssh-ed25519",
                        .blob = pub_blob,
                        .signature = null,
                    } }).write(&buf);
                    try writer.sendRaw(buf.items);
                }

                const probe = try reader.recvRaw();
                if (probe.len == 0) return error.InvalidData;
                switch (try messages.MessageType.fromByte(probe[0])) {
                    .UserauthPkOk => {},
                    .UserauthFailure => return error.AuthenticationFailure,
                    else => return error.UnexpectedMessageType,
                }

                // Sign and send.
                const sig_bytes2 = try user_auth.signUserauth(
                    kp, &session_id, ek.username, service_name, pub_blob, allocator,
                );
                var buf = std.ArrayList(u8).init(allocator);
                defer buf.deinit();
                try (user_auth.UserauthRequest{ .PublicKey = .{
                    .username = ek.username,
                    .service_name = service_name,
                    .algorithm = "ssh-ed25519",
                    .blob = pub_blob,
                    .signature = .{ .header = "ssh-ed25519", .content = &sig_bytes2 },
                } }).write(&buf);
                try writer.sendRaw(buf.items);
            },
        }

        // Both auth paths end here: read UserauthSuccess or UserauthFailure.
        const auth_result = try reader.recvRaw();
        if (auth_result.len == 0) return error.InvalidData;
        switch (try messages.MessageType.fromByte(auth_result[0])) {
            .UserauthSuccess => {},
            .UserauthFailure => return error.AuthenticationFailure,
            else => return error.UnexpectedMessageType,
        }

        return .{
            .allocator = allocator,
            .reader = reader,
            .writer = writer,
            .next_client_channel = 0,
        };
    }

    /// Connect to `address`, perform the SSH handshake, and authenticate.
    /// Convenience wrapper around `std.net.tcpConnectToAddress` + `init`.
    pub fn connectTcp(
        allocator: std.mem.Allocator,
        address: std.net.Address,
        auth: Auth,
    ) !Connection {
        const stream = try std.net.tcpConnectToAddress(address);
        return Connection.init(allocator, stream, auth);
    }

    pub fn deinit(self: *Connection) void {
        self.reader.deinit();
        self.writer.deinit();
    }

    /// Set the TCP read/write timeout (milliseconds).
    /// After this call, blocking reads that exceed the timeout return `error.Timeout`.
    /// Pass 0 to disable the timeout.
    pub fn setTimeout(self: *Connection, timeout_ms: u32) !void {
        const timeval = std.posix.timeval{
            .sec = @intCast(timeout_ms / 1000),
            .usec = @intCast((timeout_ms % 1000) * 1000),
        };
        try std.posix.setsockopt(
            self.reader.stream.handle,
            std.posix.SOL.SOCKET,
            std.posix.SO.RCVTIMEO,
            std.mem.asBytes(&timeval),
        );
    }

    /// Open a session channel and run `command`.
    /// Pass environment variables as `env = &.{ .{ "NAME", "VALUE" }, ... }`.
    pub fn run(
        self: *Connection,
        command: []const u8,
        env: []const [2][]const u8,
    ) !run_mod.RunResult {
        return run_mod.runCommand(self, command, env);
    }

    /// Run `command`, collect stdout+stderr, and return the output.
    /// Returns `null` if the server refused to open the channel.
    /// Caller owns the returned slice (free with `allocator.free`).
    pub fn quickRunBytes(
        self: *Connection,
        allocator: std.mem.Allocator,
        command: []const u8,
    ) !?struct { output: []u8, status: ?run_mod.ExitStatus } {
        return quickRunInternal(self, allocator, command, true);
    }

    /// Run `command`, collect stdout+stderr as a UTF-8 string.
    /// Returns `null` if refused. Caller owns the returned slice.
    pub fn quickRun(
        self: *Connection,
        allocator: std.mem.Allocator,
        command: []const u8,
    ) !?struct { output: []u8, status: ?run_mod.ExitStatus } {
        return quickRunInternal(self, allocator, command, true);
    }

    /// Run `command` and discard output; return only the exit status.
    /// Returns `null` if the server refused the channel.
    pub fn quickRunBlind(
        self: *Connection,
        command: []const u8,
    ) !?run_mod.ExitStatus {
        const result = try quickRunInternal(self, self.allocator, command, false);
        if (result) |res| return res.status;
        return null;
    }
};

fn quickRunInternal(
    conn: *Connection,
    allocator: std.mem.Allocator,
    command: []const u8,
    collect_output: bool,
) !?struct { output: []u8, status: ?run_mod.ExitStatus } {
    const result = try run_mod.runCommand(conn, command, &.{});
    switch (result) {
        .Refused => return null,
        .Accepted => |*run| {
            var r = run.*;
            defer r.deinit();

            var output = std.ArrayList(u8).init(allocator);
            errdefer output.deinit();

            while (true) {
                const ev = try r.poll();
                switch (ev) {
                    .None => std.time.sleep(10 * std.time.ns_per_ms),
                    .Data => |data| if (collect_output) try output.appendSlice(data),
                    .ExtDataStderr => |data| if (collect_output) try output.appendSlice(data),
                    .Stopped => |status| {
                        return .{
                            .output = try output.toOwnedSlice(),
                            .status = status,
                        };
                    },
                }
            }
        },
    }
}

// ---- Key derivation (RFC 4253 §7.2) ----

const KeyExchangeOutput = struct {
    c2s_iv: [16]u8,
    s2c_iv: [16]u8,
    c2s_key: [32]u8,
    s2c_key: [32]u8,
    c2s_hmac: [32]u8,
    s2c_hmac: [32]u8,
};

/// Derive N bytes of key material via repeated SHA-256 hashing.
fn sha256Key(
    dumped_secret: []const u8,
    exchange_hash: []const u8,
    magic: u8,
    session_id: []const u8,
    comptime N: usize,
) [N]u8 {
    var out: [N]u8 = undefined;
    var progress: usize = 0;

    var h = Sha256.init(.{});
    h.update(dumped_secret);
    h.update(exchange_hash);
    h.update(&[_]u8{magic});
    h.update(session_id);
    var block: [32]u8 = undefined;
    h.final(&block);

    while (progress < N) {
        const copy_len = @min(block.len, N - progress);
        @memcpy(out[progress..][0..copy_len], block[0..copy_len]);
        progress += copy_len;
        if (progress < N) {
            var h2 = Sha256.init(.{});
            h2.update(dumped_secret);
            h2.update(exchange_hash);
            h2.update(out[0..progress]);
            h2.final(&block);
        }
    }

    return out;
}

fn deriveKeys(
    allocator: std.mem.Allocator,
    shared_secret: *const [32]u8,
    exchange_hash: *const [32]u8,
    session_id: *const [32]u8,
) !KeyExchangeOutput {
    var ds_buf = std.ArrayList(u8).init(allocator);
    defer ds_buf.deinit();
    try wire.writeMpInt(&ds_buf, shared_secret);
    const ds = ds_buf.items;

    return .{
        .c2s_iv   = sha256Key(ds, exchange_hash, 'A', session_id, 16),
        .s2c_iv   = sha256Key(ds, exchange_hash, 'B', session_id, 16),
        .c2s_key  = sha256Key(ds, exchange_hash, 'C', session_id, 32),
        .s2c_key  = sha256Key(ds, exchange_hash, 'D', session_id, 32),
        .c2s_hmac = sha256Key(ds, exchange_hash, 'E', session_id, 32),
        .s2c_hmac = sha256Key(ds, exchange_hash, 'F', session_id, 32),
    };
}
