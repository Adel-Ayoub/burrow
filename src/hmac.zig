/// HMAC-SHA256 with cloneable state.
const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Hmac = struct {
    ih: Sha256,
    output_xor: [64]u8,

    pub fn init(key: []const u8) Hmac {
        var padded: [64]u8 = [_]u8{0} ** 64;

        if (key.len > 64) {
            var h = Sha256.init(.{});
            h.update(key);
            h.final(padded[0..32]);
        } else {
            @memcpy(padded[0..key.len], key);
        }

        var input_xor: [64]u8 = padded;
        var output_xor: [64]u8 = padded;
        for (&input_xor) |*b| b.* ^= 0x36;
        for (&output_xor) |*b| b.* ^= 0x5C;

        var ih = Sha256.init(.{});
        ih.update(&input_xor);

        return .{ .ih = ih, .output_xor = output_xor };
    }

    pub fn update(self: *Hmac, data: []const u8) void {
        self.ih.update(data);
    }

    pub fn final(self: Hmac, out: *[32]u8) void {
        var inner: [32]u8 = undefined;
        var ih_copy = self.ih;
        ih_copy.final(&inner);

        var oh = Sha256.init(.{});
        oh.update(&self.output_xor);
        oh.update(&inner);
        oh.final(out);
    }
};
