const std = @import("std");
const connection = @import("connection.zig");
const messages = @import("messages.zig");
const channel_request = @import("channel_request.zig");
const wire = @import("wire.zig");

pub const ExitStatus = u32;

pub const RunResult = union(enum) {
    Refused,
    Accepted: Run,
};

const CLIENT_INITIAL_WINDOW_SIZE: u32 = std.math.maxInt(u32);
const CLIENT_WIN_TELL_TRIGGER: u32 = CLIENT_INITIAL_WINDOW_SIZE / 4;
const CLIENT_MAX_PACKET_SIZE: u32 = 64 * 0x1000;

pub const RunEvent = union(enum) {
    /// No event yet (non-blocking / timed-out read).
    None,
    /// Data arrived on stdout.
    Data: []const u8,
    /// Data arrived on stderr (extended data type 1).
    ExtDataStderr: []const u8,
    /// Process exited; holds the exit status if the server reported one.
    Stopped: ?ExitStatus,
};

pub const Run = struct {
    conn: *connection.Connection,
    server_channel: u32,
    client_channel: u32,
    exit_status: ?ExitStatus,
    closed: bool,
    client_window: usize,
    server_window: usize,
    server_max_packet_size: usize,

    /// Poll for the next event without blocking (returns `.None` on timeout).
    pub fn poll(self: *Run) !RunEvent {
        const payload = self.conn.reader.recvRaw() catch |err| switch (err) {
            error.WouldBlock => return .None,
            else => return err,
        };

        if (payload.len == 0) return error.InvalidData;
        const msg_type = try messages.MessageType.fromByte(payload[0]);
        var r = wire.Reader.init(payload[1..]);

        switch (msg_type) {
            .ChannelData => {
                const msg = try messages.ChannelData.parse(&r);
                self.client_window -|= msg.data.len;
                if (self.client_window < CLIENT_WIN_TELL_TRIGGER) {
                    try self.sendWindowAdjust(
                        CLIENT_INITIAL_WINDOW_SIZE - @as(u32, @intCast(self.client_window)),
                    );
                    self.client_window = CLIENT_INITIAL_WINDOW_SIZE;
                }
                return .{ .Data = msg.data };
            },
            .ChannelWindowAdjust => {
                const msg = try messages.ChannelWindowAdjust.parse(&r);
                self.server_window += msg.bytes_to_add;
                return .None;
            },
            .ChannelEof => return .None,
            .ChannelClose => {
                var buf = std.ArrayList(u8).init(self.conn.allocator);
                defer buf.deinit();
                try (messages.ChannelClose{ .recipient_channel = self.server_channel }).write(&buf);
                try self.conn.writer.sendRaw(buf.items);
                self.closed = true;
                return .{ .Stopped = self.exit_status };
            },
            .ChannelRequest => {
                const req = try channel_request.ChannelRequest.parse(&r);
                if (req == .ExitStatus) self.exit_status = req.ExitStatus.exit_status;
                return .None;
            },
            .ChannelExtendedData => {
                const msg = try messages.ChannelExtendedData.parse(&r);
                if (msg.data_type == 1) return .{ .ExtDataStderr = msg.data };
                return .None;
            },
            else => return error.UnexpectedMessageType,
        }
    }

    /// Send `data` to the remote process.
    /// If the server's window is exhausted, blocks in `poll()` until space opens.
    /// If `poll()` returns an event other than `.None`, calls `onEvent(event)`.
    /// `onEvent` has signature `fn(RunEvent) anyerror!void`.
    pub fn writePoll(self: *Run, data: []const u8, onEvent: anytype) !void {
        if (self.closed) return error.ProcessHasExited;
        var remaining = data;
        while (remaining.len > 0) {
            const step = @min(
                self.server_max_packet_size,
                @min(self.server_window, remaining.len),
            );
            if (step > 0) {
                var buf = std.ArrayList(u8).init(self.conn.allocator);
                defer buf.deinit();
                try (messages.ChannelData{
                    .recipient_channel = self.server_channel,
                    .data = remaining[0..step],
                }).write(&buf);
                try self.conn.writer.sendRaw(buf.items);
                self.server_window -= step;
                remaining = remaining[step..];
            } else {
                const ev = try self.poll();
                if (ev != .None) try onEvent(ev);
            }
        }
    }

    /// Send `data` to the remote process.
    /// Returns `on_event_err` if any event arrives while waiting for window space.
    pub fn write(self: *Run, data: []const u8, on_event_err: anyerror) !void {
        if (self.closed) return error.ProcessHasExited;
        var remaining = data;
        while (remaining.len > 0) {
            const step = @min(
                self.server_max_packet_size,
                @min(self.server_window, remaining.len),
            );
            if (step > 0) {
                var buf = std.ArrayList(u8).init(self.conn.allocator);
                defer buf.deinit();
                try (messages.ChannelData{
                    .recipient_channel = self.server_channel,
                    .data = remaining[0..step],
                }).write(&buf);
                try self.conn.writer.sendRaw(buf.items);
                self.server_window -= step;
                remaining = remaining[step..];
            } else {
                const ev = try self.poll();
                switch (ev) {
                    .None => {},
                    else => return on_event_err,
                }
            }
        }
    }

    /// Close the channel if it hasn't been closed already.
    pub fn deinit(self: *Run) void {
        if (!self.closed) {
            var buf = std.ArrayList(u8).init(self.conn.allocator);
            defer buf.deinit();
            (messages.ChannelClose{ .recipient_channel = self.server_channel }).write(&buf) catch return;
            self.conn.writer.sendRaw(buf.items) catch {};
        }
    }

    fn sendWindowAdjust(self: *Run, bytes_to_add: u32) !void {
        var buf = std.ArrayList(u8).init(self.conn.allocator);
        defer buf.deinit();
        try (messages.ChannelWindowAdjust{
            .recipient_channel = self.server_channel,
            .bytes_to_add = bytes_to_add,
        }).write(&buf);
        try self.conn.writer.sendRaw(buf.items);
    }
};

/// Open a session channel and exec `command`.
/// Returns `.Refused` if the server won't open the channel or exec the command.
pub fn runCommand(
    conn: *connection.Connection,
    command: []const u8,
    env: []const [2][]const u8,
) !RunResult {
    const client_channel = conn.next_client_channel;
    conn.next_client_channel += 1;

    {
        var buf = std.ArrayList(u8).init(conn.allocator);
        defer buf.deinit();
        try (messages.ChannelOpen{
            .channel_type = "session",
            .client_channel = client_channel,
            .client_initial_window_size = CLIENT_INITIAL_WINDOW_SIZE,
            .client_max_packet_size = CLIENT_MAX_PACKET_SIZE,
        }).write(&buf);
        try conn.writer.sendRaw(buf.items);
    }

    const confirm_payload = try conn.reader.recvRaw();
    if (confirm_payload.len == 0) return error.InvalidData;
    switch (try messages.MessageType.fromByte(confirm_payload[0])) {
        .ChannelOpenConfirmation => {},
        .ChannelOpenFailure => return .Refused,
        else => return error.UnexpectedMessageType,
    }
    var cr = wire.Reader.init(confirm_payload[1..]);
    const confirm = try messages.ChannelOpenConfirmation.parse(&cr);

    for (env) |pair| {
        var buf = std.ArrayList(u8).init(conn.allocator);
        defer buf.deinit();
        try (channel_request.ChannelRequest{ .EnvironmentVariable = .{
            .recipient_channel = confirm.server_channel,
            .want_reply = false,
            .name = pair[0],
            .value = pair[1],
        } }).write(&buf);
        try conn.writer.sendRaw(buf.items);
    }

    {
        var buf = std.ArrayList(u8).init(conn.allocator);
        defer buf.deinit();
        try (channel_request.ChannelRequest{ .Exec = .{
            .recipient_channel = confirm.server_channel,
            .want_reply = true,
            .command = command,
        } }).write(&buf);
        try conn.writer.sendRaw(buf.items);
    }

    const exec_reply = try conn.reader.recvRaw();
    if (exec_reply.len == 0) return error.InvalidData;
    return switch (try messages.MessageType.fromByte(exec_reply[0])) {
        .ChannelSuccess => .{
            .Accepted = Run{
                .conn = conn,
                .server_channel = confirm.server_channel,
                .client_channel = client_channel,
                .exit_status = null,
                .closed = false,
                .client_window = CLIENT_INITIAL_WINDOW_SIZE,
                .server_window = confirm.server_initial_window_size,
                .server_max_packet_size = confirm.server_max_packet_size,
            },
        },
        .ChannelFailure => .Refused,
        else => error.UnexpectedMessageType,
    };
}

/// Open a session channel, request a PTY, then start a login shell.
pub fn openShell(
    conn: *connection.Connection,
    term: []const u8,
    cols: u32,
    rows: u32,
) !RunResult {
    const client_channel = conn.next_client_channel;
    conn.next_client_channel += 1;

    {
        var buf = std.ArrayList(u8).init(conn.allocator);
        defer buf.deinit();
        try (messages.ChannelOpen{
            .channel_type = "session",
            .client_channel = client_channel,
            .client_initial_window_size = CLIENT_INITIAL_WINDOW_SIZE,
            .client_max_packet_size = CLIENT_MAX_PACKET_SIZE,
        }).write(&buf);
        try conn.writer.sendRaw(buf.items);
    }

    const confirm_payload = try conn.reader.recvRaw();
    if (confirm_payload.len == 0) return error.InvalidData;
    switch (try messages.MessageType.fromByte(confirm_payload[0])) {
        .ChannelOpenConfirmation => {},
        .ChannelOpenFailure => return .Refused,
        else => return error.UnexpectedMessageType,
    }
    var cr = wire.Reader.init(confirm_payload[1..]);
    const confirm = try messages.ChannelOpenConfirmation.parse(&cr);

    // Request a PTY
    {
        var buf = std.ArrayList(u8).init(conn.allocator);
        defer buf.deinit();
        try (channel_request.ChannelRequest{ .PtyReq = .{
            .recipient_channel = confirm.server_channel,
            .want_reply = true,
            .term = term,
            .width_chars = cols,
            .height_rows = rows,
            .width_pixels = 0,
            .height_pixels = 0,
            .modes = &[_]u8{0}, // TTY_OP_END
        } }).write(&buf);
        try conn.writer.sendRaw(buf.items);
    }
    {
        const pty_reply = try conn.reader.recvRaw();
        if (pty_reply.len == 0) return error.InvalidData;
        switch (try messages.MessageType.fromByte(pty_reply[0])) {
            .ChannelSuccess => {},
            .ChannelFailure => return .Refused,
            else => return error.UnexpectedMessageType,
        }
    }

    // Start shell
    {
        var buf = std.ArrayList(u8).init(conn.allocator);
        defer buf.deinit();
        try (channel_request.ChannelRequest{ .Shell = .{
            .recipient_channel = confirm.server_channel,
            .want_reply = true,
        } }).write(&buf);
        try conn.writer.sendRaw(buf.items);
    }

    const shell_reply = try conn.reader.recvRaw();
    if (shell_reply.len == 0) return error.InvalidData;
    return switch (try messages.MessageType.fromByte(shell_reply[0])) {
        .ChannelSuccess => .{
            .Accepted = Run{
                .conn = conn,
                .server_channel = confirm.server_channel,
                .client_channel = client_channel,
                .exit_status = null,
                .closed = false,
                .client_window = CLIENT_INITIAL_WINDOW_SIZE,
                .server_window = confirm.server_initial_window_size,
                .server_max_packet_size = confirm.server_max_packet_size,
            },
        },
        .ChannelFailure => .Refused,
        else => error.UnexpectedMessageType,
    };
}
