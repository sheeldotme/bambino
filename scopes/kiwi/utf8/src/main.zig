const std = @import("std");
const testing = std.testing;
const simd = std.simd;

const Vector = @Vector(16, u8);

fn isAscii(vector: Vector) bool {
    const mask: Vector = @splat(0x80);
    const zeroes: Vector = @splat(0);
    return @reduce(.And, (vector & mask) == zeroes);
}

test "validate ASCII characters" {
    try testing.expectEqual(true, isAscii(simd.iota(u8, @sizeOf(Vector))));
    try testing.expectEqual(true, isAscii(@splat(127)));
    try testing.expectEqual(false, isAscii(@splat(128)));
}
