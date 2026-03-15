const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

const HEX_CHARS = "0123456789abcdef";

fn hexNibble(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// Decode a hex string of exactly N*2 characters into N bytes.
pub fn decodeHex(comptime N: usize, hex: []const u8) ?[N]u8 {
    if (hex.len != N * 2) return null;
    var out: [N]u8 = undefined;
    for (0..N) |i| {
        const hi = hexNibble(hex[i * 2]) orelse return null;
        const lo = hexNibble(hex[i * 2 + 1]) orelse return null;
        out[i] = (hi << 4) | lo;
    }
    return out;
}

/// Generate a new Ed25519 keypair.
/// Returns a 128-character hex string (64 bytes: seed || public_key).
/// Caller owns the returned slice.
pub fn createEd25519Keypair(allocator: std.mem.Allocator) ![]u8 {
    var seed: [Ed25519.KeyPair.seed_length]u8 = undefined;
    std.crypto.random.bytes(&seed);
    const kp = try Ed25519.KeyPair.generateDeterministic(seed);

    var raw: [64]u8 = undefined;
    @memcpy(raw[0..32], &seed);
    @memcpy(raw[32..64], &kp.public_key.toBytes());

    const hex = try allocator.alloc(u8, 128);
    for (raw, 0..) |byte, i| {
        hex[i * 2] = HEX_CHARS[(byte >> 4) & 0xf];
        hex[i * 2 + 1] = HEX_CHARS[byte & 0xf];
    }
    return hex;
}

/// Produce the OpenSSH authorized_keys line for the public key in hex_keypair.
/// Caller owns the returned slice.
pub fn dumpEd25519PkOpenssh(
    allocator: std.mem.Allocator,
    hex_keypair: []const u8,
    username: []const u8,
) ![]u8 {
    const raw = decodeHex(64, hex_keypair) orelse return error.InvalidKeypair;
    const seed = raw[0..32];
    const kp = try Ed25519.KeyPair.generateDeterministic(seed.*);

    var blob_buf: [4 + 11 + 4 + 32]u8 = undefined;
    const algo = "ssh-ed25519";
    std.mem.writeInt(u32, blob_buf[0..4], @intCast(algo.len), .big);
    @memcpy(blob_buf[4..15], algo);
    std.mem.writeInt(u32, blob_buf[15..19], 32, .big);
    @memcpy(blob_buf[19..51], &kp.public_key.toBytes());

    const b64 = std.base64.standard_no_pad.Encoder;
    const encoded_len = b64.calcSize(blob_buf.len);
    const out = try allocator.alloc(u8, "ssh-ed25519 ".len + encoded_len + 1 + username.len + 1);
    var pos: usize = 0;
    @memcpy(out[pos .. pos + 12], "ssh-ed25519 ");
    pos += 12;
    _ = b64.encode(out[pos .. pos + encoded_len], &blob_buf);
    pos += encoded_len;
    out[pos] = ' ';
    pos += 1;
    @memcpy(out[pos .. pos + username.len], username);
    pos += username.len;
    out[pos] = '\n';
    return out;
}
