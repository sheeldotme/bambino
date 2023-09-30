const std = @import("std");

const RawPacket = struct {
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: [4]u8,
    secs: [2]u8,
    flags: [2]u8,
    ciaddr: [4]u8,
    yiaddr: [4]u8,
    siaddr: [4]u8,
    giaddr: [4]u8,
    chaddr: [16]u8,
    sname: [64]u8,
    file: [128]u8,
    vend: [64]u8,
};

inline fn contains(comptime T: type, array: []const T, value: T) bool {
    for (array) |item| {
        if (item == value) return true;
    }
    return false;
}

const PacketParsingError = error{
    OpValueNotSupported,
    HtypeValueNotSupported,
    HlenValueNotSupported,
    FlagsValueNotSupported,
    SnameValueNotSupported,
    FileValueNotSupported,
};

fn parse_packet(bytes: []const u8) !*const RawPacket {
    const packet: *const RawPacket = @alignCast(@ptrCast(bytes.ptr));

    if (packet.op != 1 and packet.op != 2) {
        return error.OpValueNotSupported;
    }

    if (packet.htype != 1) {
        return error.HtypeValueNotSupported;
    }

    if (packet.hlen != 6) {
        return error.HlenValueNotSupported;
    }

    if (packet.flags[0] != 0 or packet.flags[1] != 0) {
        return error.FlagsValueNotSupported;
    }

    if (!contains(u8, &packet.sname, 0)) {
        return error.SnameValueNotSupported;
    }

    if (!contains(u8, &packet.file, 0)) {
        return error.FileValueNotSupported;
    }

    return packet;
}

const testing = std.testing;

test "Test Packet Parsing Errors" {
    const good_packet = [_]u8{1} // op
    ++ [_]u8{1} // htype
    ++ [_]u8{6} // hlen
    ++ [_]u8{0} // hops
    ++ [_]u8{0} ** 4 // xid
    ++ [_]u8{0} ** 2 // secs
    ++ [_]u8{0} ** 2 // flags
    ++ [_]u8{0} ** 4 // ciaddr
    ++ [_]u8{0} ** 4 // yiaddr
    ++ [_]u8{0} ** 4 // siaddr
    ++ [_]u8{0} ** 4 // giaddr
    ++ [_]u8{0} ** 16 // chaddr
    ++ [_]u8{0} ** 64 // sname
    ++ [_]u8{0} ** 128 // file
    ++ [_]u8{0} ** 64; // vend

    const bad_packet = [_]u8{0} // op
    ++ [_]u8{0} // htype
    ++ [_]u8{0} // hlen
    ++ [_]u8{0} // hops
    ++ [_]u8{0} ** 4 // xid
    ++ [_]u8{0} ** 2 // secs
    ++ [_]u8{1} ** 2 // flags
    ++ [_]u8{0} ** 4 // ciaddr
    ++ [_]u8{0} ** 4 // yiaddr
    ++ [_]u8{0} ** 4 // siaddr
    ++ [_]u8{0} ** 4 // giaddr
    ++ [_]u8{0} ** 16 // chaddr
    ++ [_]u8{1} ** 64 // sname
    ++ [_]u8{1} ** 128 // file
    ++ [_]u8{0} ** 64; // vend

    try testing.expectError(error.OpValueNotSupported, parse_packet(&bad_packet));
    try testing.expectError(error.HtypeValueNotSupported, parse_packet(good_packet[0..1] ++ bad_packet[1..]));
    try testing.expectError(error.HlenValueNotSupported, parse_packet(good_packet[0..2] ++ bad_packet[2..]));
    try testing.expectError(error.FlagsValueNotSupported, parse_packet(good_packet[0..10] ++ bad_packet[10..]));
    try testing.expectError(error.FlagsValueNotSupported, parse_packet(good_packet[0..11] ++ bad_packet[11..]));
    try testing.expectError(error.SnameValueNotSupported, parse_packet(good_packet[0..44] ++ bad_packet[44..]));
    try testing.expectError(error.FileValueNotSupported, parse_packet(good_packet[0..108] ++ bad_packet[108..]));
}
