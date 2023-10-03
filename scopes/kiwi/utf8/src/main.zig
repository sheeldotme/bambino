const std = @import("std");

/// Returns true if the given bytes are all ASCII. \
/// precondition: N > 0
pub fn isAscii(comptime N: usize, bytes: []const u8) bool {
    comptime {
        if (N == 0) @compileError("N can't be zero");
    }

    const Vector = @Vector(N, u8);

    const mask: Vector = @splat(0x80);
    const zeroes: Vector = @splat(0);
    var it = std.mem.window(u8, bytes, N, N);
    while (it.next()) |window| {
        if (window.len < N) break;
        if (!@reduce(.And, (window[0..N].* & mask) == zeroes)) return false;
    }

    var paddedVector: Vector = zeroes;
    const remainder = bytes[bytes.len - (bytes.len % N) ..];
    const paddedArray: [*]u8 = @ptrCast(&paddedVector);
    std.mem.copy(u8, paddedArray[0..remainder.len], remainder);
    return @reduce(.And, (paddedVector & mask) == zeroes);
}

test "isAscii" {
    const expect = std.testing.expect;

    // Boundary conditions
    try expect(isAscii(1, &[_]u8{0}) == true);
    try expect(isAscii(1, &[_]u8{127}) == true);
    try expect(isAscii(1, &[_]u8{128}) == false);

    // Empty input
    try expect(isAscii(1, &[_]u8{}) == true);

    // Input that is a multiple of N
    try expect(isAscii(4, &[_]u8{ 65, 66, 67, 68 }) == true);
    try expect(isAscii(4, &[_]u8{ 125, 126, 127, 128 }) == false);
    try expect(isAscii(4, &[_]u8{ 125, 126, 128, 127 }) == false);
    try expect(isAscii(4, &[_]u8{ 125, 128, 126, 127 }) == false);
    try expect(isAscii(4, &[_]u8{ 128, 125, 126, 127 }) == false);

    // Input that is not a multiple of N
    try expect(isAscii(4, &[_]u8{ 65, 66, 67, 68, 69 }) == true);
    try expect(isAscii(4, &[_]u8{ 124, 125, 126, 127, 128 }) == false);
    try expect(isAscii(4, &[_]u8{ 124, 125, 126, 128, 127 }) == false);
    try expect(isAscii(4, &[_]u8{ 124, 125, 128, 126, 127 }) == false);
    try expect(isAscii(4, &[_]u8{ 124, 128, 125, 126, 127 }) == false);
    try expect(isAscii(4, &[_]u8{ 128, 124, 125, 126, 127 }) == false);
}
