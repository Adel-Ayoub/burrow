/// SSH 2.0 message type constants and message parsing/encoding.
const std = @import("std");
const wire = @import("wire.zig");

pub const MessageType = enum(u8) {
    Disconnect = 1,
    Ignore = 2,
    Unimplemented = 3,
    Debug = 4,
    ServiceRequest = 5,
    ServiceAccept = 6,
    Kexinit = 20,
    Newkeys = 21,
    KexdhInit = 30,
    KexdhReply = 31,
    UserauthRequest = 50,
    UserauthFailure = 51,
    UserauthSuccess = 52,
    UserauthBanner = 53,
    UserauthPkOk = 60,
    GlobalRequest = 80,
    RequestSuccess = 81,
    RequestFailure = 82,
    ChannelOpen = 90,
    ChannelOpenConfirmation = 91,
    ChannelOpenFailure = 92,
    ChannelWindowAdjust = 93,
    ChannelData = 94,
    ChannelExtendedData = 95,
    ChannelEof = 96,
    ChannelClose = 97,
    ChannelRequest = 98,
    ChannelSuccess = 99,
    ChannelFailure = 100,

    pub fn fromByte(b: u8) !MessageType {
        return switch (b) {
            1 => .Disconnect,
            2 => .Ignore,
            3 => .Unimplemented,
            4 => .Debug,
            5 => .ServiceRequest,
            6 => .ServiceAccept,
            20 => .Kexinit,
            21 => .Newkeys,
            30 => .KexdhInit,
            31 => .KexdhReply,
            50 => .UserauthRequest,
            51 => .UserauthFailure,
            52 => .UserauthSuccess,
            53 => .UserauthBanner,
            60 => .UserauthPkOk,
            80 => .GlobalRequest,
            81 => .RequestSuccess,
            82 => .RequestFailure,
            90 => .ChannelOpen,
            91 => .ChannelOpenConfirmation,
            92 => .ChannelOpenFailure,
            93 => .ChannelWindowAdjust,
            94 => .ChannelData,
            95 => .ChannelExtendedData,
            96 => .ChannelEof,
            97 => .ChannelClose,
            98 => .ChannelRequest,
            99 => .ChannelSuccess,
            100 => .ChannelFailure,
            else => error.UnknownMessageType,
        };
    }
};

pub const Kexinit = struct {
    cookie: [16]u8,
    kex_algorithms: []const u8,
    server_host_key_algorithms: []const u8,
    encryption_algorithms_client_to_server: []const u8,
    encryption_algorithms_server_to_client: []const u8,
    mac_algorithms_client_to_server: []const u8,
    mac_algorithms_server_to_client: []const u8,
    compression_algorithms_client_to_server: []const u8,
    compression_algorithms_server_to_client: []const u8,
    languages_client_to_server: []const u8,
    languages_server_to_client: []const u8,
    first_kex_packet_follows: bool,
    nop: u32,

    pub fn parse(r: *wire.Reader) !Kexinit {
        return .{
            .cookie = try r.readFixed(16),
            .kex_algorithms = try r.readStr(),
            .server_host_key_algorithms = try r.readStr(),
            .encryption_algorithms_client_to_server = try r.readStr(),
            .encryption_algorithms_server_to_client = try r.readStr(),
            .mac_algorithms_client_to_server = try r.readStr(),
            .mac_algorithms_server_to_client = try r.readStr(),
            .compression_algorithms_client_to_server = try r.readStr(),
            .compression_algorithms_server_to_client = try r.readStr(),
            .languages_client_to_server = try r.readStr(),
            .languages_server_to_client = try r.readStr(),
            .first_kex_packet_follows = try r.readBool(),
            .nop = try r.readU32(),
        };
    }

    pub fn write(self: Kexinit, buf: *std.ArrayList(u8)) !void {
        try wire.writeU8(buf, @intFromEnum(MessageType.Kexinit));
        try wire.writeRaw(buf, &self.cookie);
        try wire.writeStr(buf, self.kex_algorithms);
        try wire.writeStr(buf, self.server_host_key_algorithms);
        try wire.writeStr(buf, self.encryption_algorithms_client_to_server);
        try wire.writeStr(buf, self.encryption_algorithms_server_to_client);
        try wire.writeStr(buf, self.mac_algorithms_client_to_server);
        try wire.writeStr(buf, self.mac_algorithms_server_to_client);
        try wire.writeStr(buf, self.compression_algorithms_client_to_server);
        try wire.writeStr(buf, self.compression_algorithms_server_to_client);
        try wire.writeStr(buf, self.languages_client_to_server);
        try wire.writeStr(buf, self.languages_server_to_client);
        try wire.writeBool(buf, self.first_kex_packet_follows);
        try wire.writeU32(buf, self.nop);
    }

    /// Check that the server supports our required algorithms.
    pub fn checkCompat(server: Kexinit, client: Kexinit) !void {
        const fields = .{
            .{ server.kex_algorithms,                          client.kex_algorithms },
            .{ server.server_host_key_algorithms,              client.server_host_key_algorithms },
            .{ server.encryption_algorithms_client_to_server,  client.encryption_algorithms_client_to_server },
            .{ server.encryption_algorithms_server_to_client,  client.encryption_algorithms_server_to_client },
            .{ server.mac_algorithms_client_to_server,         client.mac_algorithms_client_to_server },
            .{ server.mac_algorithms_server_to_client,         client.mac_algorithms_server_to_client },
            .{ server.compression_algorithms_client_to_server, client.compression_algorithms_client_to_server },
            .{ server.compression_algorithms_server_to_client, client.compression_algorithms_server_to_client },
        };
        inline for (fields) |pair| {
            if (!algListContains(pair[0], pair[1]))
                return error.Unimplemented;
        }
    }
};

fn algListContains(list: []const u8, needle: []const u8) bool {
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |alg| {
        if (std.mem.eql(u8, alg, needle)) return true;
    }
    return false;
}

pub const KexdhInit = struct {
    client_ephemeral_pubkey: []const u8,

    pub fn write(self: KexdhInit, buf: *std.ArrayList(u8)) !void {
        try wire.writeU8(buf, @intFromEnum(MessageType.KexdhInit));
        try wire.writeBytes(buf, self.client_ephemeral_pubkey);
    }
};

pub const Blob = struct {
    header: []const u8,
    content: []const u8,

    pub fn parse(r: *wire.Reader) !Blob {
        const total_len = try r.readU32();
        const start = r.pos;
        const header = try r.readStr();
        const content = try r.readBytes();
        if (r.pos != start + total_len) return error.InvalidData;
        return .{ .header = header, .content = content };
    }

    pub fn write(self: Blob, buf: *std.ArrayList(u8)) !void {
        // blob_len = 4 (header len) + header.len + 4 (content len) + content.len
        const blob_len: u32 = @intCast(4 + self.header.len + 4 + self.content.len);
        try wire.writeU32(buf, blob_len);
        try wire.writeStr(buf, self.header);
        try wire.writeBytes(buf, self.content);
    }
};

pub const KexdhReply = struct {
    server_public_host_key: Blob,
    server_ephemeral_pubkey: []const u8,
    exchange_hash_signature: Blob,

    pub fn parse(r: *wire.Reader) !KexdhReply {
        return .{
            .server_public_host_key = try Blob.parse(r),
            .server_ephemeral_pubkey = try r.readBytes(),
            .exchange_hash_signature = try Blob.parse(r),
        };
    }
};

pub const ServiceRequest = struct {
    service_name: []const u8,

    pub fn write(self: ServiceRequest, buf: *std.ArrayList(u8)) !void {
        try wire.writeU8(buf, @intFromEnum(MessageType.ServiceRequest));
        try wire.writeStr(buf, self.service_name);
    }
};

pub const ChannelOpen = struct {
    channel_type: []const u8,
    client_channel: u32,
    client_initial_window_size: u32,
    client_max_packet_size: u32,

    pub fn write(self: ChannelOpen, buf: *std.ArrayList(u8)) !void {
        try wire.writeU8(buf, @intFromEnum(MessageType.ChannelOpen));
        try wire.writeStr(buf, self.channel_type);
        try wire.writeU32(buf, self.client_channel);
        try wire.writeU32(buf, self.client_initial_window_size);
        try wire.writeU32(buf, self.client_max_packet_size);
    }
};

pub const ChannelOpenConfirmation = struct {
    client_channel: u32,
    server_channel: u32,
    server_initial_window_size: u32,
    server_max_packet_size: u32,

    pub fn parse(r: *wire.Reader) !ChannelOpenConfirmation {
        return .{
            .client_channel = try r.readU32(),
            .server_channel = try r.readU32(),
            .server_initial_window_size = try r.readU32(),
            .server_max_packet_size = try r.readU32(),
        };
    }
};

pub const ChannelOpenFailure = struct {
    client_channel: u32,
    reason_code: u32,
    description: []const u8,
    language_tag: []const u8,

    pub fn parse(r: *wire.Reader) !ChannelOpenFailure {
        return .{
            .client_channel = try r.readU32(),
            .reason_code = try r.readU32(),
            .description = try r.readStr(),
            .language_tag = try r.readStr(),
        };
    }
};

pub const ChannelData = struct {
    recipient_channel: u32,
    data: []const u8,

    pub fn parse(r: *wire.Reader) !ChannelData {
        return .{
            .recipient_channel = try r.readU32(),
            .data = try r.readBytes(),
        };
    }

    pub fn write(self: ChannelData, buf: *std.ArrayList(u8)) !void {
        try wire.writeU8(buf, @intFromEnum(MessageType.ChannelData));
        try wire.writeU32(buf, self.recipient_channel);
        try wire.writeBytes(buf, self.data);
    }
};

pub const ChannelExtendedData = struct {
    recipient_channel: u32,
    data_type: u32,
    data: []const u8,

    pub fn parse(r: *wire.Reader) !ChannelExtendedData {
        return .{
            .recipient_channel = try r.readU32(),
            .data_type = try r.readU32(),
            .data = try r.readBytes(),
        };
    }
};

pub const ChannelWindowAdjust = struct {
    recipient_channel: u32,
    bytes_to_add: u32,

    pub fn parse(r: *wire.Reader) !ChannelWindowAdjust {
        return .{
            .recipient_channel = try r.readU32(),
            .bytes_to_add = try r.readU32(),
        };
    }

    pub fn write(self: ChannelWindowAdjust, buf: *std.ArrayList(u8)) !void {
        try wire.writeU8(buf, @intFromEnum(MessageType.ChannelWindowAdjust));
        try wire.writeU32(buf, self.recipient_channel);
        try wire.writeU32(buf, self.bytes_to_add);
    }
};

pub const ChannelEof = struct {
    recipient_channel: u32,

    pub fn parse(r: *wire.Reader) !ChannelEof {
        return .{ .recipient_channel = try r.readU32() };
    }
};

pub const ChannelClose = struct {
    recipient_channel: u32,

    pub fn parse(r: *wire.Reader) !ChannelClose {
        return .{ .recipient_channel = try r.readU32() };
    }

    pub fn write(self: ChannelClose, buf: *std.ArrayList(u8)) !void {
        try wire.writeU8(buf, @intFromEnum(MessageType.ChannelClose));
        try wire.writeU32(buf, self.recipient_channel);
    }
};

pub const ChannelSuccess = struct {
    recipient_channel: u32,

    pub fn parse(r: *wire.Reader) !ChannelSuccess {
        return .{ .recipient_channel = try r.readU32() };
    }
};

pub const ChannelFailure = struct {
    recipient_channel: u32,

    pub fn parse(r: *wire.Reader) !ChannelFailure {
        return .{ .recipient_channel = try r.readU32() };
    }
};

pub const GlobalRequest = struct {
    request_name: []const u8,
    want_reply: bool,

    pub fn parse(r: *wire.Reader) !GlobalRequest {
        return .{
            .request_name = try r.readStr(),
            .want_reply = try r.readBool(),
        };
    }
};

pub const UserauthFailure = struct {
    allowed_auth: []const u8,
    partial_success: bool,

    pub fn parse(r: *wire.Reader) !UserauthFailure {
        return .{
            .allowed_auth = try r.readStr(),
            .partial_success = try r.readBool(),
        };
    }
};

pub const UserauthPkOk = struct {
    algorithm: []const u8,
    blob: Blob,

    pub fn parse(r: *wire.Reader) !UserauthPkOk {
        return .{
            .algorithm = try r.readStr(),
            .blob = try Blob.parse(r),
        };
    }
};
