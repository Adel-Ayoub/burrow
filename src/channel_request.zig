const std = @import("std");
const wire = @import("wire.zig");
const messages = @import("messages.zig");

pub const ChannelRequest = union(enum) {
    Exec: struct {
        recipient_channel: u32,
        want_reply: bool,
        command: []const u8,
    },
    EnvironmentVariable: struct {
        recipient_channel: u32,
        want_reply: bool,
        name: []const u8,
        value: []const u8,
    },
    ExitStatus: struct {
        recipient_channel: u32,
        exit_status: u32,
    },
    PtyReq: struct {
        recipient_channel: u32,
        want_reply: bool,
        term: []const u8,
        width_chars: u32,
        height_rows: u32,
        width_pixels: u32,
        height_pixels: u32,
        modes: []const u8,
    },
    Shell: struct {
        recipient_channel: u32,
        want_reply: bool,
    },
    WindowChange: struct {
        recipient_channel: u32,
        width_chars: u32,
        height_rows: u32,
        width_pixels: u32,
        height_pixels: u32,
    },
    Other: struct {
        recipient_channel: u32,
        request_type: []const u8,
        want_reply: bool,
    },

    pub fn parse(r: *wire.Reader) !ChannelRequest {
        const recipient_channel = try r.readU32();
        const request_type = try r.readStr();
        const want_reply = try r.readBool();

        if (std.mem.eql(u8, request_type, "exec")) {
            return .{ .Exec = .{
                .recipient_channel = recipient_channel,
                .want_reply = want_reply,
                .command = try r.readStr(),
            } };
        } else if (std.mem.eql(u8, request_type, "env")) {
            return .{ .EnvironmentVariable = .{
                .recipient_channel = recipient_channel,
                .want_reply = want_reply,
                .name = try r.readStr(),
                .value = try r.readStr(),
            } };
        } else if (std.mem.eql(u8, request_type, "exit-status")) {
            if (want_reply) return error.InvalidData;
            return .{ .ExitStatus = .{
                .recipient_channel = recipient_channel,
                .exit_status = try r.readU32(),
            } };
        } else {
            return .{ .Other = .{
                .recipient_channel = recipient_channel,
                .request_type = request_type,
                .want_reply = want_reply,
            } };
        }
    }

    pub fn write(self: ChannelRequest, buf: *std.ArrayList(u8)) !void {
        try wire.writeU8(buf, @intFromEnum(messages.MessageType.ChannelRequest));
        switch (self) {
            .Exec => |e| {
                try wire.writeU32(buf, e.recipient_channel);
                try wire.writeStr(buf, "exec");
                try wire.writeBool(buf, e.want_reply);
                try wire.writeStr(buf, e.command);
            },
            .EnvironmentVariable => |e| {
                try wire.writeU32(buf, e.recipient_channel);
                try wire.writeStr(buf, "env");
                try wire.writeBool(buf, e.want_reply);
                try wire.writeStr(buf, e.name);
                try wire.writeStr(buf, e.value);
            },
            .ExitStatus => |e| {
                try wire.writeU32(buf, e.recipient_channel);
                try wire.writeStr(buf, "exit-status");
                try wire.writeBool(buf, false);
                try wire.writeU32(buf, e.exit_status);
            },
            .PtyReq => |p| {
                try wire.writeU32(buf, p.recipient_channel);
                try wire.writeStr(buf, "pty-req");
                try wire.writeBool(buf, p.want_reply);
                try wire.writeStr(buf, p.term);
                try wire.writeU32(buf, p.width_chars);
                try wire.writeU32(buf, p.height_rows);
                try wire.writeU32(buf, p.width_pixels);
                try wire.writeU32(buf, p.height_pixels);
                try wire.writeBytes(buf, p.modes);
            },
            .Shell => |s| {
                try wire.writeU32(buf, s.recipient_channel);
                try wire.writeStr(buf, "shell");
                try wire.writeBool(buf, s.want_reply);
            },
            .WindowChange => |w| {
                try wire.writeU32(buf, w.recipient_channel);
                try wire.writeStr(buf, "window-change");
                try wire.writeBool(buf, false);
                try wire.writeU32(buf, w.width_chars);
                try wire.writeU32(buf, w.height_rows);
                try wire.writeU32(buf, w.width_pixels);
                try wire.writeU32(buf, w.height_pixels);
            },
            .Other => return error.InvalidData,
        }
    }
};
