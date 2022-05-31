const std = @import("std");
const zig_dis_x86_64 = @import("zig-dis-x86_64");

var gpa_alloc = std.heap.GeneralPurposeAllocator(.{}){};
const gpa = gpa_alloc.allocator();

pub fn main() !void {
    const args = try std.process.argsAlloc(gpa);
    defer std.process.argsFree(gpa, args);

    const input_hex = args[1];
    const hex_len = @divExact(input_hex.len, 2);

    var i: usize = 0;
    var bytes = std.ArrayList(u8).init(gpa);
    try bytes.ensureTotalCapacity(hex_len);
    defer bytes.deinit();

    while (i < hex_len) : (i += 1) {
        const next_hex = input_hex[i * 2 .. (i + 1) * 2];
        bytes.appendAssumeCapacity(try std.fmt.parseInt(u8, next_hex, 16));
    }

    const inst = try zig_dis_x86_64.disassembleSingle(bytes.items);

    var buf = std.ArrayList(u8).init(gpa);
    defer buf.deinit();
    try inst.fmtPrint(buf.writer());

    std.log.warn("disassembled: {s}  {s}", .{ input_hex, buf.items });
}
