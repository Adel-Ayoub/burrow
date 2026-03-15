/// Stateful AES-256-CTR cipher.
/// Lower 64 bits of the counter block (bytes 8-15) are incremented after each block.
const std = @import("std");
const Aes256 = std.crypto.core.aes.Aes256;

pub const Aes256Ctr64Be = struct {
    ctx: std.crypto.core.aes.AesEncryptCtx(Aes256),
    counter: [16]u8,
    keystream: [16]u8,
    pos: usize,

    pub fn init(key: [32]u8, iv: [16]u8) Aes256Ctr64Be {
        return .{
            .ctx = Aes256.initEnc(key),
            .counter = iv,
            .keystream = undefined,
            .pos = 16, // force generation on first call
        };
    }

    pub fn applyKeystream(self: *Aes256Ctr64Be, data: []u8) void {
        for (data) |*byte| {
            if (self.pos == 16) {
                self.ctx.encrypt(&self.keystream, &self.counter);
                // Increment low 64 bits big-endian (bytes 8-15)
                var i: usize = 15;
                while (true) {
                    self.counter[i] +%= 1;
                    if (self.counter[i] != 0 or i == 8) break;
                    i -= 1;
                }
                self.pos = 0;
            }
            byte.* ^= self.keystream[self.pos];
            self.pos += 1;
        }
    }
};
