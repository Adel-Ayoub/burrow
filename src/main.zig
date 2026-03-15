const std = @import("std");
const posix = std.posix;
const burrow = @import("root.zig");

const usage =
    \\Usage: burrow [options] [user@]host
    \\
    \\Options:
    \\  -p PORT     Port (default: 22)
    \\  -i KEYFILE  Ed25519 hex keypair file
    \\
;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const stderr = std.io.getStdErr().writer();

    // ---- Parse arguments ----
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    var port: u16 = 22;
    var keyfile: ?[]const u8 = null;
    var target: ?[]const u8 = null;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-p")) {
            i += 1;
            if (i >= args.len) { try stderr.writeAll(usage); return; }
            port = std.fmt.parseInt(u16, args[i], 10) catch {
                try stderr.writeAll("Invalid port\n");
                return;
            };
        } else if (std.mem.eql(u8, arg, "-i")) {
            i += 1;
            if (i >= args.len) { try stderr.writeAll(usage); return; }
            keyfile = args[i];
        } else if (arg[0] != '-') {
            target = arg;
        } else {
            try stderr.writeAll(usage);
            return;
        }
    }

    const dest = target orelse {
        try stderr.writeAll(usage);
        return;
    };

    // Split user@host
    var username: []const u8 = undefined;
    var host: []const u8 = undefined;
    if (std.mem.indexOf(u8, dest, "@")) |at| {
        username = dest[0..at];
        host = dest[at + 1 ..];
    } else {
        host = dest;
        // Fall back to $USER
        username = std.posix.getenv("USER") orelse {
            try stderr.writeAll("Cannot determine username; use user@host\n");
            return;
        };
    }

    // ---- Build auth ----
    var auth: burrow.Auth = undefined;
    var key_buf: ?[]u8 = null;
    defer if (key_buf) |k| allocator.free(k);

    if (keyfile) |path| {
        key_buf = std.fs.cwd().readFileAlloc(allocator, path, 256) catch {
            try stderr.print("Cannot read key file: {s}\n", .{path});
            return;
        };
        const trimmed = std.mem.trim(u8, key_buf.?, &[_]u8{ '\n', '\r', ' ', '\t' });
        auth = .{ .ed25519 = .{ .username = username, .hex_keypair = trimmed } };
    } else {
        const pw = readPassword(stderr) catch {
            try stderr.writeAll("Failed to read password\n");
            return;
        };
        auth = .{ .password = .{ .username = username, .password = pw } };
    }

    // ---- Connect ----
    try stderr.print("Connecting to {s}:{d}...\n", .{ host, port });

    const stream = std.net.tcpConnectToHost(allocator, host, port) catch |err| {
        try stderr.print("Connection failed: {s}\n", .{@errorName(err)});
        return;
    };

    var conn = burrow.Connection.init(allocator, stream, auth) catch |err| {
        try stderr.print("SSH handshake failed: {s}\n", .{@errorName(err)});
        return;
    };
    defer conn.deinit();

    // ---- Terminal size ----
    const ws = getWinsize();
    const cols: u32 = if (ws.col > 0) ws.col else 80;
    const rows: u32 = if (ws.row > 0) ws.row else 24;

    // ---- Open interactive shell ----
    const term = std.posix.getenv("TERM") orelse "xterm-256color";
    const result = try burrow.run.openShell(&conn, term, cols, rows);
    var session = switch (result) {
        .Refused => {
            try stderr.writeAll("Server refused shell request\n");
            return;
        },
        .Accepted => |r| r,
    };
    defer session.deinit();

    // ---- Raw terminal mode ----
    const orig_termios = enableRawMode() catch {
        try stderr.writeAll("Cannot set raw terminal mode\n");
        return;
    };
    defer restoreTermMode(orig_termios);

    // ---- I/O loop (single-threaded with poll) ----
    const stdout = std.io.getStdOut();
    const socket_fd = conn.reader.stream.handle;
    var stdin_buf: [4096]u8 = undefined;

    while (true) {
        var fds = [_]posix.pollfd{
            .{ .fd = posix.STDIN_FILENO, .events = posix.POLL.IN, .revents = 0 },
            .{ .fd = socket_fd, .events = posix.POLL.IN, .revents = 0 },
        };

        _ = posix.poll(&fds, -1) catch break;

        // Stdin → remote
        if (fds[0].revents & posix.POLL.IN != 0) {
            const n = posix.read(posix.STDIN_FILENO, &stdin_buf) catch break;
            if (n == 0) break;
            sendChannelData(&conn, session.server_channel, stdin_buf[0..n], allocator) catch break;
        }

        // Remote → stdout
        if (fds[1].revents & posix.POLL.IN != 0) {
            const ev = session.poll() catch break;
            switch (ev) {
                .Data => |data| stdout.writeAll(data) catch break,
                .ExtDataStderr => |data| stdout.writeAll(data) catch break,
                .Stopped => break,
                .None => {},
            }
        }

        if (fds[1].revents & posix.POLL.HUP != 0) break;
    }
}

fn sendChannelData(
    conn: *burrow.Connection,
    server_channel: u32,
    data: []const u8,
    allocator: std.mem.Allocator,
) !void {
    var buf = std.ArrayList(u8).init(allocator);
    defer buf.deinit();
    try (burrow.messages.ChannelData{
        .recipient_channel = server_channel,
        .data = data,
    }).write(&buf);
    try conn.writer.sendRaw(buf.items);
}

fn enableRawMode() !posix.termios {
    const orig = try posix.tcgetattr(posix.STDIN_FILENO);
    var raw = orig;

    raw.lflag.ECHO = false;
    raw.lflag.ICANON = false;
    raw.lflag.ISIG = false;
    raw.lflag.IEXTEN = false;

    raw.iflag.IXON = false;
    raw.iflag.ICRNL = false;
    raw.iflag.BRKINT = false;
    raw.iflag.INPCK = false;
    raw.iflag.ISTRIP = false;

    raw.oflag.OPOST = false;

    raw.cc[@intFromEnum(posix.V.MIN)] = 1;
    raw.cc[@intFromEnum(posix.V.TIME)] = 0;

    try posix.tcsetattr(posix.STDIN_FILENO, .FLUSH, raw);
    return orig;
}

fn restoreTermMode(orig: posix.termios) void {
    posix.tcsetattr(posix.STDIN_FILENO, .FLUSH, orig) catch {};
}

fn readPassword(stderr: anytype) ![]const u8 {
    try stderr.writeAll("Password: ");

    const orig = try posix.tcgetattr(posix.STDIN_FILENO);
    var no_echo = orig;
    no_echo.lflag.ECHO = false;
    try posix.tcsetattr(posix.STDIN_FILENO, .FLUSH, no_echo);
    defer posix.tcsetattr(posix.STDIN_FILENO, .FLUSH, orig) catch {};

    var buf: [256]u8 = undefined;
    const stdin = std.io.getStdIn().reader();
    const line = try stdin.readUntilDelimiter(&buf, '\n');
    try stderr.writeAll("\n");
    return line;
}

fn getWinsize() posix.winsize {
    var ws: posix.winsize = .{ .row = 0, .col = 0, .xpixel = 0, .ypixel = 0 };
    _ = posix.system.ioctl(posix.STDOUT_FILENO, posix.T.IOCGWINSZ, @intFromPtr(&ws));
    return ws;
}
