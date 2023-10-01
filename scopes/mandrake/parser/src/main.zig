const std = @import("std");

/// A BOOTP packet
const RawPacket = struct {
    /// Operation code
    op: u8,
    /// Hardware type
    htype: u8,
    /// Hardware address length
    hlen: u8,
    /// Hops
    hops: u8,
    /// Transaction ID
    xid: [4]u8,
    /// Seconds
    secs: [2]u8,
    /// Flags
    flags: [2]u8,
    /// Client IP address
    ciaddr: [4]u8,
    /// Your IP address
    yiaddr: [4]u8,
    /// Server IP address
    siaddr: [4]u8,
    /// Gateway IP address
    giaddr: [4]u8,
    /// Client hardware address
    chaddr: [16]u8,
    /// Server name
    sname: [64]u8,
    /// Boot file name
    file: [128]u8,
    /// Vendor specific information
    vend: [64]u8,
};

/// A BOOTP operation
const Operation = enum(u8) {
    /// A client request
    BootRequest = 1,
    /// A server reply
    BootReply = 2,
};

/// A BOOTP hardware type
/// https://www.iana.org/assignments/arp-parameters/arp-parameters.xhtml#arp-parameters-2
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

/// A parsed BOOTP packet
/// https://datatracker.ietf.org/doc/html/rfc951#section-3
const Packet = struct {
    /// The BOOTP operation code eg. BOOTREQUEST & BOOTREPLY.
    operation: Operation,
    /// The hardware type eg. Ethernet
    hardware_type: HardwareType,
    /// The hardware address length in bytes
    hardware_address_length: u8,
    /// The number of hops the packet has taken
    hops: u8,
    /// The client assigned transaction ID
    transaction_id: u32,
    /// The number of seconds since the client began the request
    seconds: u16,
    /// Extra flags eg. broadcast flag (0x8000)
    flags: u16,
    /// The IP address the client is requesting
    client_ip_address: u32,
    /// The IP address the server is assigning to the client
    your_ip_address: u32,
    /// The IP address of the server
    server_ip_address: u32,
    /// The IP address of the gateway
    gateway_ip_address: u32,
    /// The client hardware address eg. the MAC address
    client_hardware_address: [16]u8,
    /// The server name eg. the TFTP server, the NFS server, etc.
    server_name: [64]u8,
    /// The boot file name eg. the kernel image, the initrd, etc.
    boot_file_name: [128]u8,
    /// The vendor specific information eg. DHCP options, PXE options, etc.
    vendor_specific_information: [64]u8,
};

/// Error codes for parsing BOOTP packets
const RequestError = error{
    /// Only BOOTREQUEST and BOOTREPLY are supported
    OperationNotSupported,
    /// Only Ethernet is supported
    HardwareTypeNotSupported,
    /// Only 6 byte hardware addresses are supported
    HardwareAddressLengthNotSupported,
    /// Flags must be 0
    FlagsNotSupported,
    /// Server name must be null terminated
    ServerNameNotProvided,
    /// Boot file name must be null terminated
    BootFileNameNotProvided,
};

/// Parses a BOOTP packet
/// https://datatracker.ietf.org/doc/html/rfc951#section-3 \
/// precondition: bytes.len == 300 \
/// precondition: out != null
fn parse_packet(bytes: []const u8, out: *Packet) !void {
    const packet: *const RawPacket = @ptrCast(bytes.ptr);

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
    ++ [_]u8{8} ** 63 ++ [_]u8{0} // sname (null terminated)
    ++ [_]u8{9} ** 127 ++ [_]u8{0} // file (null terminated)
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
    try testing.expectEqual(out.operation, .BootRequest);
    try testing.expectEqual(out.hardware_type, .Ethernet);
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
