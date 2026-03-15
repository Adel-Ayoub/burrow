/// SSH binary wire format: reading and writing primitives.
const std = @import("std");

pub fn writeU8(buf: *std.ArrayList(u8), v: u8) !void {
    try buf.append(v);
}

pub fn writeU32(buf: *std.ArrayList(u8), v: u32) !void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .big);
    try buf.appendSlice(&b);
}

pub fn writeBool(buf: *std.ArrayList(u8), v: bool) !void {
    try buf.append(if (v) 1 else 0);
}

/// SSH string: 4-byte length prefix + bytes.
pub fn writeBytes(buf: *std.ArrayList(u8), data: []const u8) !void {
    try writeU32(buf, @intCast(data.len));
    try buf.appendSlice(data);
}

pub fn writeStr(buf: *std.ArrayList(u8), s: []const u8) !void {
    try writeBytes(buf, s);
}

/// SSH fixed array (no length prefix).
pub fn writeRaw(buf: *std.ArrayList(u8), data: []const u8) !void {
    try buf.appendSlice(data);
}

/// SSH mpint: unsigned big-endian integer with 4-byte length prefix.
/// Prepends 0x00 if MSB of the leading byte is set (to indicate positive).
pub fn writeMpInt(buf: *std.ArrayList(u8), data: []const u8) !void {
    var start: usize = 0;
    while (start < data.len and data[start] == 0) start += 1;

    if (start == data.len) {
        try writeU32(buf, 0);
        return;
    }

    const needs_pad = (data[start] & 0x80) != 0;
    const content_len = data.len - start + @as(usize, if (needs_pad) 1 else 0);
    try writeU32(buf, @intCast(content_len));
    if (needs_pad) try buf.append(0);
    try buf.appendSlice(data[start..]);
}

pub const Reader = struct {
    data: []const u8,
    pos: usize,

    pub fn init(data: []const u8) Reader {
        return .{ .data = data, .pos = 0 };
    }

    pub fn readU8(self: *Reader) !u8 {
        if (self.pos >= self.data.len) return error.UnexpectedEof;
        defer self.pos += 1;
        return self.data[self.pos];
    }

    pub fn readU32(self: *Reader) !u32 {
        if (self.pos + 4 > self.data.len) return error.UnexpectedEof;
        const v = std.mem.readInt(u32, self.data[self.pos..][0..4], .big);
        self.pos += 4;
        return v;
    }

    pub fn readBool(self: *Reader) !bool {
        return (try self.readU8()) != 0;
    }

    /// Reads a length-prefixed byte slice (SSH string / mpint-like blob).
    pub fn readBytes(self: *Reader) ![]const u8 {
        const len = try self.readU32();
        if (self.pos + len > self.data.len) return error.UnexpectedEof;
        const slice = self.data[self.pos..][0..len];
        self.pos += len;
        return slice;
    }

    /// Reads a length-prefixed UTF-8 string.
    pub fn readStr(self: *Reader) ![]const u8 {
        const bytes = try self.readBytes();
        if (!std.unicode.utf8ValidateSlice(bytes)) return error.InvalidData;
        return bytes;
    }

    /// Reads exactly N raw bytes (no length prefix).
    pub fn readFixed(self: *Reader, comptime N: usize) ![N]u8 {
        if (self.pos + N > self.data.len) return error.UnexpectedEof;
        const arr = self.data[self.pos..][0..N].*;
        self.pos += N;
        return arr;
    }

    pub fn readRaw(self: *Reader, len: usize) ![]const u8 {
        if (self.pos + len > self.data.len) return error.UnexpectedEof;
        const s = self.data[self.pos..][0..len];
        self.pos += len;
        return s;
    }

    pub fn skip(self: *Reader, n: usize) !void {
        if (self.pos + n > self.data.len) return error.UnexpectedEof;
        self.pos += n;
    }
};
