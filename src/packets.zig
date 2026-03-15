/// SSH binary packet framing: reads and writes length-padded,
/// encrypted-and-MAC'd packets over a TCP stream.
const std = @import("std");
const cipher_mod = @import("cipher.zig");
const hmac_mod = @import("hmac.zig");
const messages = @import("messages.zig");
const wire = @import("wire.zig");

const Cipher = cipher_mod.Aes256Ctr64Be;
const Hmac = hmac_mod.Hmac;

pub const PacketReader = struct {
    stream: std.net.Stream,
    packet: std.ArrayList(u8),
    packet_number: u32,
    cipher: ?Cipher,
    hmac: ?Hmac,
    block_size: usize,
    mac_size: usize,

    pub fn init(allocator: std.mem.Allocator, stream: std.net.Stream) PacketReader {
        return .{
            .stream = stream,
            .packet = std.ArrayList(u8).init(allocator),
            .packet_number = 0,
            .cipher = null,
            .hmac = null,
            .block_size = 8,
            .mac_size = 0,
        };
    }

    pub fn deinit(self: *PacketReader) void {
        self.packet.deinit();
    }

    pub fn setDecryptor(self: *PacketReader, c: Cipher, h: Hmac, block_size: usize, mac_size: usize) void {
        self.cipher = c;
        self.hmac = h;
        self.block_size = block_size;
        self.mac_size = mac_size;
    }

    fn pull(self: *PacketReader, n: usize) !void {
        const old_len = self.packet.items.len;
        try self.packet.resize(old_len + n);
        try self.stream.reader().readNoEof(self.packet.items[old_len..]);
    }

    fn pullDecrypt(self: *PacketReader, n: usize) !void {
        const old_len = self.packet.items.len;
        try self.pull(n);
        if (self.cipher) |*c| c.applyKeystream(self.packet.items[old_len..]);
    }

    /// Receive the next meaningful payload (message type byte + body).
    /// Transparently drops Ignore, Debug, and UserauthBanner packets.
    /// Transparently drops GlobalRequest packets (without sending a reply).
    /// Returns `error.ConnectionReset` on Disconnect.
    pub fn recvRaw(self: *PacketReader) ![]const u8 {
        while (true) {
            self.packet.clearRetainingCapacity();

            try self.pullDecrypt(4);
            const packet_length = std.mem.readInt(u32, self.packet.items[0..4], .big);
            if (packet_length < 2 or packet_length > 35000) return error.InvalidData;

            try self.pullDecrypt(packet_length);

            if (self.mac_size != 0) {
                try self.pull(self.mac_size);
            }

            const padding_length = self.packet.items[4];
            if (packet_length < @as(u32, 1) + padding_length) return error.InvalidData;

            const payload_length: usize = packet_length - 1 - padding_length;
            const payload_offset: usize = 5; // [packet_length:4][padding_length:1]

            if (self.hmac) |base_hmac| {
                var h = base_hmac;
                var pn_bytes: [4]u8 = undefined;
                std.mem.writeInt(u32, &pn_bytes, self.packet_number, .big);
                h.update(&pn_bytes);
                const packet_end: usize = 4 + packet_length;
                h.update(self.packet.items[0..packet_end]);
                var computed: [32]u8 = undefined;
                h.final(&computed);
                const received = self.packet.items[packet_end..][0..self.mac_size];
                if (!std.mem.eql(u8, &computed, received)) return error.InvalidData;
            }

            self.packet_number +%= 1;

            if (payload_length == 0) return error.InvalidData;

            const payload = self.packet.items[payload_offset..][0..payload_length];
            const msg_type = try messages.MessageType.fromByte(payload[0]);

            switch (msg_type) {
                .Ignore, .Debug, .UserauthBanner => continue,
                .Disconnect => return error.ConnectionReset,
                // Drop GlobalRequest; we cannot send RequestFailure here without a
                // reference to the writer, so we silently ignore both variants.
                .GlobalRequest => continue,
                else => return payload,
            }
        }
    }

    /// Like `recvRaw`, but maps `WouldBlock` to `error.Timeout` and optionally
    /// asserts the message type, returning only the body (after the type byte).
    pub fn recv(self: *PacketReader, expect: ?messages.MessageType) ![]const u8 {
        const payload = self.recvRaw() catch |err| switch (err) {
            error.WouldBlock => return error.Timeout,
            else => return err,
        };
        if (payload.len == 0) return error.InvalidData;
        const got = try messages.MessageType.fromByte(payload[0]);
        if (expect) |e| {
            if (got != e) return error.UnexpectedMessageType;
        }
        return payload[1..];
    }
};

pub const PacketWriter = struct {
    stream: std.net.Stream,
    packet: std.ArrayList(u8),
    packet_number: u32,
    cipher: ?Cipher,
    hmac: ?Hmac,
    block_size: usize,

    pub fn init(allocator: std.mem.Allocator, stream: std.net.Stream) PacketWriter {
        return .{
            .stream = stream,
            .packet = std.ArrayList(u8).init(allocator),
            .packet_number = 0,
            .cipher = null,
            .hmac = null,
            .block_size = 8,
        };
    }

    pub fn deinit(self: *PacketWriter) void {
        self.packet.deinit();
    }

    pub fn setEncryptor(self: *PacketWriter, c: Cipher, h: Hmac, block_size: usize) void {
        self.cipher = c;
        self.hmac = h;
        self.block_size = block_size;
    }

    /// Serialize `payload` into an SSH packet and write it to the stream.
    /// `payload` must already include the message-type byte as its first byte.
    pub fn sendRaw(self: *PacketWriter, payload: []const u8) !void {
        self.packet.clearRetainingCapacity();

        const payload_len = payload.len;
        const unpadded = 4 + 1 + payload_len; // packet_length field + padding_length byte + payload

        const remainder = unpadded % self.block_size;
        var padding_length: usize = if (remainder == 0) 0 else self.block_size - remainder;
        if (padding_length < 4) padding_length += self.block_size;

        const packet_length: u32 = @intCast(1 + payload_len + padding_length);

        var pl_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &pl_bytes, packet_length, .big);
        try self.packet.appendSlice(&pl_bytes);
        try self.packet.append(@intCast(padding_length));
        try self.packet.appendSlice(payload);
        try self.packet.appendNTimes(0, padding_length);

        var mac_bytes: [32]u8 = undefined;
        if (self.hmac) |base_hmac| {
            var h = base_hmac;
            var pn_bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &pn_bytes, self.packet_number, .big);
            h.update(&pn_bytes);
            h.update(self.packet.items);
            h.final(&mac_bytes);
        }

        if (self.cipher) |*c| c.applyKeystream(self.packet.items);

        self.packet_number +%= 1;

        try self.stream.writeAll(self.packet.items);
        if (self.hmac != null) try self.stream.writeAll(&mac_bytes);
    }
};
