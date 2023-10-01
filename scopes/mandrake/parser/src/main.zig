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

const PacketOperation = enum(u8) {
    BootRequest = 1,
    BootReply = 2,
};

const HardwareType = enum(u8) {
    Reserved = 0,
    Ethernet = 1,
    ExperimentalEthernet = 2,
    AmateurRadioAX25 = 3,
    ProteonProNETTokenRing = 4,
    Chaos = 5,
    IEEE802Networks = 6,
    ARCNET = 7,
    Hyperchannel = 8,
    Lanstar = 9,
    AutonetShortAddress = 10,
    LocalTalk = 11,
    LocalNet = 12,
    UltraLink = 13,
    SMDS = 14,
    FrameRelay = 15,
    AsynchronousTransmissionMode1 = 16,
    HDLC = 17,
    FibreChannel = 18,
    AsynchronousTransmissionMode2 = 19,
    SerialLine = 20,
    AsynchronousTransmissionMode3 = 21,
    MILSTD188220 = 22,
    Metricom = 23,
    IEEE1394dot1995 = 24,
    MAPOS = 25,
    Twinaxial = 26,
    EUI64 = 27,
    HIPARP = 28,
    IPandARPoverISO7816_3 = 29,
    ARPSec = 30,
    IPsecTunnel = 31,
    InfiniBand = 32,
    TIA102Project25CommonAirInterface = 33,
    WiegandInterface = 34,
    PureIP = 35,
    HWExp1 = 36,
    HFI = 37,
    UnifiedBus = 38,
};

const Packet = struct {
    operation: PacketOperation,
    hardware_type: HardwareType,
    hardware_address_length: u8,
    hops: u8,
    transaction_id: u32,
    seconds: u16,
    flags: u16,
    client_ip_address: u32,
    your_ip_address: u32,
    server_ip_address: u32,
    gateway_ip_address: u32,
    client_hardware_address: [16]u8,
    server_name: [64]u8,
    boot_file_name: [128]u8,
    vendor_specific_information: [64]u8,
};

const RequestError = error{
    OperationNotSupported,
    HardwareTypeNotSupported,
    HardwareAddressLengthNotSupported,
    FlagsNotSupported,
    ServerNameNotProvided,
    BootFileNameNotProvided,
};

/// Parses a BOOTP packet
/// https://tools.ietf.org/html/rfc951
/// precondition: bytes.len == 300
/// precondition: out != null
fn parse_packet(bytes: []const u8, out: *Packet) !void {
    const packet: *const RawPacket = @alignCast(@ptrCast(bytes.ptr));

    if (packet.op != 1 and packet.op != 2) return error.OperationNotSupported;
    if (packet.htype != 1) return error.HardwareTypeNotSupported;
    if (packet.hlen != 6) return error.HardwareAddressLengthNotSupported;
    if (packet.flags[0] != 0 or packet.flags[1] != 0) return error.FlagsNotSupported;

    _ = std.mem.indexOfScalar(u8, &packet.sname, 0) orelse return error.ServerNameInvalid;
    _ = std.mem.indexOfScalar(u8, &packet.file, 0) orelse return error.BootFileNameInvalid;

    out.operation = @enumFromInt(packet.op);
    out.hardware_type = @enumFromInt(packet.htype);
    out.hardware_address_length = packet.hlen;
    out.hops = packet.hops;
    out.transaction_id = std.mem.readIntBig(u32, &packet.xid);
    out.seconds = std.mem.readIntBig(u16, &packet.secs);
    out.flags = std.mem.readIntBig(u16, &packet.flags);
    out.client_ip_address = std.mem.readIntBig(u32, &packet.ciaddr);
    out.your_ip_address = std.mem.readIntBig(u32, &packet.yiaddr);
    out.server_ip_address = std.mem.readIntBig(u32, &packet.siaddr);
    out.gateway_ip_address = std.mem.readIntBig(u32, &packet.giaddr);
    out.client_hardware_address = packet.chaddr;
    out.server_name = packet.sname;
    out.boot_file_name = packet.file;
    out.vendor_specific_information = packet.vend;
}

const testing = std.testing;

test "Test Packet Parsing Errors" {
    const good_packet = [_]u8{1} // op
    ++ [_]u8{1} // htype
    ++ [_]u8{6} // hlen
    ++ [_]u8{0} // hops
    ++ [_]u8{1} ** 4 // xid
    ++ [_]u8{2} ** 2 // secs
    ++ [_]u8{0} ** 2 // flags
    ++ [_]u8{3} ** 4 // ciaddr
    ++ [_]u8{4} ** 4 // yiaddr
    ++ [_]u8{5} ** 4 // siaddr
    ++ [_]u8{6} ** 4 // giaddr
    ++ [_]u8{7} ** 16 // chaddr
    ++ [_]u8{8} ** 63 ++ [_]u8{0} // sname
    ++ [_]u8{9} ** 127 ++ [_]u8{0} // file
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

    var out: Packet = undefined;

    try testing.expectError(error.OperationNotSupported, parse_packet(&bad_packet, &out));
    try testing.expectError(error.HardwareTypeNotSupported, parse_packet(good_packet[0..1] ++ bad_packet[1..], &out));
    try testing.expectError(error.HardwareAddressLengthNotSupported, parse_packet(good_packet[0..2] ++ bad_packet[2..], &out));
    try testing.expectError(error.FlagsNotSupported, parse_packet(good_packet[0..10] ++ bad_packet[10..], &out));
    try testing.expectError(error.FlagsNotSupported, parse_packet(good_packet[0..11] ++ bad_packet[11..], &out));
    try testing.expectError(error.ServerNameInvalid, parse_packet(good_packet[0..44] ++ bad_packet[44..], &out));
    try testing.expectError(error.BootFileNameInvalid, parse_packet(good_packet[0..108] ++ bad_packet[108..], &out));

    try parse_packet(&good_packet, &out);
    try testing.expectEqual(out.operation, PacketOperation.BootRequest);
    try testing.expectEqual(out.hardware_type, HardwareType.Ethernet);
    try testing.expectEqual(out.hardware_address_length, 6);
    try testing.expectEqual(out.hops, 0);
    try testing.expectEqual(out.transaction_id, 0x01010101);
    try testing.expectEqual(out.seconds, 0x0202);
    try testing.expectEqual(out.flags, 0);
    try testing.expectEqual(out.client_ip_address, 0x03030303);
    try testing.expectEqual(out.your_ip_address, 0x04040404);
    try testing.expectEqual(out.server_ip_address, 0x05050505);
    try testing.expectEqual(out.gateway_ip_address, 0x06060606);
    try testing.expectEqual(out.client_hardware_address, [_]u8{7} ** 16);
    try testing.expectEqual(out.server_name, [_]u8{8} ** 63 ++ [_]u8{0});
    try testing.expectEqual(out.boot_file_name, [_]u8{9} ** 127 ++ [_]u8{0});
    try testing.expectEqual(out.vendor_specific_information, [_]u8{0} ** 64);
}
