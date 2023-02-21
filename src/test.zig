const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const testing = std.testing;

const dis_x86_64 = @import("dis_x86_64.zig");
const Disassembler = dis_x86_64.Disassembler;
const Instruction = dis_x86_64.Instruction;
const Memory = dis_x86_64.Memory;
const Mnemonic = dis_x86_64.Mnemonic;
const Moffs = dis_x86_64.Moffs;
const Operand = Instruction.Operand;

// Decoder tests
// zig fmt: on

// test "disassemble" {
//     var disassembler = Disassembler.init(&.{
//         // zig fmt: off
//         0x40, 0xb7, 0x10,                                           // mov dil, 0x10
//         0x49, 0xbc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, // mov r12, 0x1000000000000000
//         0xb8, 0x00, 0x00, 0x00, 0x10,                               // mov eax, 0x10000000
//         0x48, 0x8b, 0xd8,                                           // mov rbx, rax
//         0x4d, 0x8b, 0xdc,                                           // mov r11, r12
//         0x49, 0x8b, 0xd4,                                           // mov rdx, r12
//         0x4d, 0x89, 0xdc,                                           // mov r12, r11
//         0x49, 0x89, 0xd4,                                           // mov r12, rdx
//         0x4c, 0x8b, 0x65, 0xf0,                                     // mov r12, QWORD PTR [rbp - 0x10]
//         0x48, 0x8b, 0x85, 0x00, 0xf0, 0xff, 0xff,                   // mov rax, QWORD PTR [rbp - 0x1000]
//         0x48, 0x8b, 0x1d, 0x00, 0x00, 0x00, 0x00,                   // mov rbx, QWORD PTR [rip]
//         0x48, 0x8b, 0x18,                                           // mov rbx, QWORD PTR [rax]
//         // zig fmt: on
//     });

//     {
//         const inst = (try disassembler.next()).?;
//         try testing.expect(inst.tag == .mov);
//         try testing.expect(inst.enc == .oi);
//         try testing.expect(inst.data.oi.reg == .bh);
//         try testing.expect(inst.data.oi.imm == 0x10);
//     }

//     {
//         const inst = (try disassembler.next()).?;
//         try testing.expect(inst.tag == .mov);
//         try testing.expect(inst.enc == .oi);
//         try testing.expect(inst.data.oi.reg == .r12);
//         try testing.expect(inst.data.oi.imm == 0x1000000000000000);
//     }

//     {
//         const inst = (try disassembler.next()).?;
//         try testing.expect(inst.tag == .mov);
//         try testing.expect(inst.enc == .oi);
//         try testing.expect(inst.data.oi.reg == .eax);
//         try testing.expect(inst.data.oi.imm == 0x10000000);
//     }

//     {
//         const inst = (try disassembler.next()).?;
//         try testing.expect(inst.tag == .mov);
//         try testing.expect(inst.enc == .rm);
//         try testing.expect(inst.data.rm.reg == .rbx);
//         try testing.expect(inst.data.rm.reg_or_mem.reg == .rax);
//     }

//     {
//         const inst = (try disassembler.next()).?;
//         try testing.expect(inst.tag == .mov);
//         try testing.expect(inst.enc == .rm);
//         try testing.expect(inst.data.rm.reg == .r11);
//         try testing.expect(inst.data.rm.reg_or_mem.reg == .r12);
//     }

//     {
//         const inst = (try disassembler.next()).?;
//         try testing.expect(inst.tag == .mov);
//         try testing.expect(inst.enc == .rm);
//         try testing.expect(inst.data.rm.reg == .rdx);
//         try testing.expect(inst.data.rm.reg_or_mem.reg == .r12);
//     }

//     {
//         const inst = (try disassembler.next()).?;
//         try testing.expect(inst.tag == .mov);
//         try testing.expect(inst.enc == .mr);
//         try testing.expect(inst.data.mr.reg_or_mem.reg == .r12);
//         try testing.expect(inst.data.mr.reg == .r11);
//     }

//     {
//         const inst = (try disassembler.next()).?;
//         try testing.expect(inst.tag == .mov);
//         try testing.expect(inst.enc == .mr);
//         try testing.expect(inst.data.mr.reg_or_mem.reg == .r12);
//         try testing.expect(inst.data.mr.reg == .rdx);
//     }

//     {
//         const inst = (try disassembler.next()).?;
//         try testing.expect(inst.tag == .mov);
//         try testing.expect(inst.enc == .rm);
//         try testing.expect(inst.data.rm.reg == .r12);
//         try testing.expect(inst.data.rm.reg_or_mem.mem.ptr_size == .qword);
//         try testing.expect(inst.data.rm.reg_or_mem.mem.scale_index == null);
//         try testing.expect(inst.data.rm.reg_or_mem.mem.base.? == .rbp);
//         try testing.expect(@intCast(i8, inst.data.rm.reg_or_mem.mem.disp) == -0x10);
//     }

//     {
//         const inst = (try disassembler.next()).?;
//         try testing.expect(inst.tag == .mov);
//         try testing.expect(inst.enc == .rm);
//         try testing.expect(inst.data.rm.reg == .rax);
//         try testing.expect(inst.data.rm.reg_or_mem.mem.ptr_size == .qword);
//         try testing.expect(inst.data.rm.reg_or_mem.mem.scale_index == null);
//         try testing.expect(inst.data.rm.reg_or_mem.mem.base.? == .rbp);
//         try testing.expect(inst.data.rm.reg_or_mem.mem.disp == -0x1000);
//     }

//     {
//         const inst = (try disassembler.next()).?;
//         try testing.expect(inst.tag == .mov);
//         try testing.expect(inst.enc == .rm);
//         try testing.expect(inst.data.rm.reg == .rbx);
//         try testing.expect(inst.data.rm.reg_or_mem.mem.ptr_size == .qword);
//         try testing.expect(inst.data.rm.reg_or_mem.mem.scale_index == null);
//         try testing.expect(inst.data.rm.reg_or_mem.mem.base == null);
//         try testing.expect(inst.data.rm.reg_or_mem.mem.disp == 0x0);
//     }

//     {
//         const inst = (try disassembler.next()).?;
//         try testing.expect(inst.tag == .mov);
//         try testing.expect(inst.enc == .rm);
//         try testing.expect(inst.data.rm.reg == .rbx);
//         try testing.expect(inst.data.rm.reg_or_mem.mem.ptr_size == .qword);
//         try testing.expect(inst.data.rm.reg_or_mem.mem.scale_index == null);
//         try testing.expect(inst.data.rm.reg_or_mem.mem.base.? == .rax);
//         try testing.expect(inst.data.rm.reg_or_mem.mem.disp == 0x0);
//     }
// }

// test "disassemble - mnemonic" {
//     const gpa = testing.allocator;
//     var disassembler = Disassembler.init(&.{
//         // zig fmt: off
//         0x48, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x41, 0xbc, 0xf0, 0xff, 0xff, 0xff,
//         0x4c, 0x8b, 0x65, 0xf0,
//         0x48, 0x8b, 0x85, 0x00, 0xf0, 0xff, 0xff,
//         0x48, 0x8b, 0x18,
//         0xc6, 0x45, 0xf0, 0x10,
//         0x49, 0xc7, 0x43, 0xf0, 0x10, 0x00, 0x00, 0x00,
//         0x4C, 0x89, 0x1d, 0xf0, 0xff, 0xff, 0xff,
//         0x49, 0x89, 0x43, 0xf0,
//         0x48, 0x8d, 0x45, 0xf0,
//         0x41, 0x8d, 0x43, 0x10,
//         0x4c, 0x8d, 0x25, 0x00, 0x00, 0x00, 0x00,
//         0x48, 0x03, 0x05, 0x00, 0x00, 0x00, 0x00,
//         0x48, 0x83, 0xc0, 0x10,
//         0x48, 0x83, 0x45, 0xf0, 0xf0,
//         0x80, 0x55, 0xf0, 0x10,
//         0x48, 0x83, 0x60, 0x10, 0x08,
//         0x48, 0x83, 0x4d, 0x10, 0x0f,
//         0x49, 0x83, 0xdb, 0x08,
//         0x49, 0x83, 0xec, 0x00,
//         0x41, 0x80, 0x73, 0xf0, 0x20,
//         0x34, 0x10,
//         0x1d, 0x00, 0x00, 0x00, 0x00,
//         0x48, 0x2d, 0x0f, 0x00, 0x00, 0x00,
//         0x66, 0x1d, 0x00, 0x10,
//         0x66, 0x25, 0xf0, 0xff,
//         0x66, 0x48, 0x25, 0xf0, 0xff, 0xff, 0xff,
//         0x65, 0x66, 0xa1, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x36, 0xa2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x26, 0xa3, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x48, 0xa1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
//         0x65, 0x44, 0x01, 0x24, 0x25, 0x00, 0x00, 0x00, 0x10,
//         0x42, 0xff, 0x14, 0x5d, 0x00, 0x00, 0x00, 0x00,
//         0x42, 0xff, 0x14, 0x65, 0x00, 0x00, 0x00, 0x00,
//         0x0f, 0xbf, 0xc3,
//         0x0f, 0xbe, 0xc3,
//         0x66, 0x0f, 0xbe, 0xc3,
//         0x48, 0x63, 0xc3,
//         0xe8, 0x00, 0x00, 0x00, 0x00,
//         // zig fmt: on
//     });

//     var buf = std.ArrayList(u8).init(gpa);
//     defer buf.deinit();

//     while (try disassembler.next()) |inst| {
//         try inst.fmtPrint(buf.writer());
//         try buf.append('\n');
//     }

//     try testing.expectEqualStrings(
//         \\movabs rax, 0x10
//         \\mov r12d, 0xfffffff0
//         \\mov r12, QWORD PTR [rbp - 0x10]
//         \\mov rax, QWORD PTR [rbp - 0x1000]
//         \\mov rbx, QWORD PTR [rax]
//         \\mov BYTE PTR [rbp - 0x10], 0x10
//         \\mov QWORD PTR [r11 - 0x10], 0x10
//         \\mov QWORD PTR [rip - 0x10], r11
//         \\mov QWORD PTR [r11 - 0x10], rax
//         \\lea rax, QWORD PTR [rbp - 0x10]
//         \\lea eax, DWORD PTR [r11 + 0x10]
//         \\lea r12, QWORD PTR [rip]
//         \\add rax, QWORD PTR [rip]
//         \\add rax, 0x10
//         \\add QWORD PTR [rbp - 0x10], 0xf0
//         \\adc BYTE PTR [rbp - 0x10], 0x10
//         \\and QWORD PTR [rax + 0x10], 0x8
//         \\or QWORD PTR [rbp + 0x10], 0xf
//         \\sbb r11, 0x8
//         \\sub r12, 0x0
//         \\xor BYTE PTR [r11 - 0x10], 0x20
//         \\xor al, 0x10
//         \\sbb eax, 0x0
//         \\sub rax, 0xf
//         \\sbb ax, 0x1000
//         \\and ax, 0xfff0
//         \\and rax, 0xfffffff0
//         \\movabs ax, gs:0x10
//         \\movabs ss:0x0, al
//         \\movabs es:0x8, eax
//         \\movabs rax, ds:0x0
//         \\add DWORD PTR gs:0x10000000, r12d
//         \\call QWORD PTR [r11 * 2]
//         \\call QWORD PTR [r12 * 2]
//         \\movsx eax, bx
//         \\movsx eax, bl
//         \\movsx ax, bl
//         \\movsxd rax, ebx
//         \\call 0x0
//         \\
//     , buf.items);
// }

// Encoder tests
// zig fmt: on

fn expectEqualHexStrings(expected: []const u8, given: []const u8, assembly: []const u8) !void {
    assert(expected.len > 0);
    if (mem.eql(u8, expected, given)) return;
    const expected_fmt = try std.fmt.allocPrint(testing.allocator, "{x}", .{std.fmt.fmtSliceHexLower(expected)});
    defer testing.allocator.free(expected_fmt);
    const given_fmt = try std.fmt.allocPrint(testing.allocator, "{x}", .{std.fmt.fmtSliceHexLower(given)});
    defer testing.allocator.free(given_fmt);
    const idx = mem.indexOfDiff(u8, expected_fmt, given_fmt).?;
    var padding = try testing.allocator.alloc(u8, idx + 5);
    defer testing.allocator.free(padding);
    mem.set(u8, padding, ' ');
    std.debug.print("\nASM: {s}\nEXP: {s}\nGIV: {s}\n{s}^ -- first differing byte\n", .{
        assembly,
        expected_fmt,
        given_fmt,
        padding,
    });
    return error.TestFailed;
}

fn expectError(args: struct {
    mnemonic: Mnemonic,
    op1: Operand = .none,
    op2: Operand = .none,
    op3: Operand = .none,
    op4: Operand = .none,
}) !void {
    const err = Instruction.new(.{
        .mnemonic = args.mnemonic,
        .op1 = args.op1,
        .op2 = args.op2,
        .op3 = args.op3,
        .op4 = args.op4,
    });
    try testing.expectError(error.InvalidInstruction, err);
}

const TestEncode = struct {
    buffer: [32]u8 = undefined,
    index: usize = 0,

    fn encode(enc: *TestEncode, args: struct {
        mnemonic: Mnemonic,
        op1: Operand = .none,
        op2: Operand = .none,
        op3: Operand = .none,
        op4: Operand = .none,
    }) !void {
        var stream = std.io.fixedBufferStream(&enc.buffer);
        var count_writer = std.io.countingWriter(stream.writer());
        const inst = try Instruction.new(.{
            .mnemonic = args.mnemonic,
            .op1 = args.op1,
            .op2 = args.op2,
            .op3 = args.op3,
            .op4 = args.op4,
        });
        try inst.encode(count_writer.writer());
        enc.index = count_writer.bytes_written;
    }

    fn code(enc: TestEncode) []const u8 {
        return enc.buffer[0..enc.index];
    }
};

test "encode" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    const inst = try Instruction.new(.{
        .mnemonic = .mov,
        .op1 = .{ .reg = .rbx },
        .op2 = .{ .imm = 4 },
    });
    try inst.encode(buf.writer());
    try testing.expectEqualSlices(u8, &.{ 0x48, 0xc7, 0xc3, 0x4, 0x0, 0x0, 0x0 }, buf.items);
}

// test "lower I encoding" {
//     var enc = TestEncode{};

//     try enc.encode(.{ .tag = .add, .enc = .i, .data = Instruction.Data.i(.al, 0x10) });
//     try expectEqualHexStrings("\x04\x10", enc.code(), "add al, 0x10");

//     try enc.encode(.{ .tag = .add, .enc = .i, .data = Instruction.Data.i(.rax, 0x10) });
//     try expectEqualHexStrings("\x48\x05\x10\x00\x00\x00", enc.code(), "add rax, 0x10");

//     try enc.encode(.{ .tag = .xor, .enc = .i, .data = Instruction.Data.i(.al, 0x10) });
//     try expectEqualHexStrings("\x34\x10", enc.code(), "xor al, 0x10");

//     try enc.encode(.{ .tag = .sbb, .enc = .i, .data = Instruction.Data.i(.ax, 0x10) });
//     try expectEqualHexStrings("\x66\x1D\x10\x00", enc.code(), "sbb ax, 0x10");
// }

test "lower MI encoding" {
    var enc = TestEncode{};

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .reg = .r12 }, .op2 = .{ .imm = 0x1000 } });
    try expectEqualHexStrings("\x49\xC7\xC4\x00\x10\x00\x00", enc.code(), "mov r12, 0x1000");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .mem = Memory.mem(.byte, .{
        .base = .r12,
        .disp = 0,
    }) }, .op2 = .{ .imm = 0x10 } });
    try expectEqualHexStrings("\x41\xC6\x04\x24\x10", enc.code(), "mov BYTE PTR [r12], 0x10");

    // try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .reg = .r12 }, .op2 = .{ .imm = 0x1000 } });
    // try expectEqualHexStrings("\x49\xC7\xC4\x00\x10\x00\x00", enc.code(), "mov r12, 0x1000");
    // try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .reg = .r12 }, .op2 = .{ .imm = 0x1000 } });
    // try expectEqualHexStrings("\x49\xC7\xC4\x00\x10\x00\x00", enc.code(), "mov r12, 0x1000");

    //     try enc.encode(.{ .tag = .mov, .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.reg(.rax), 0x10, 32) });
    //     try expectEqualHexStrings("\x48\xc7\xc0\x10\x00\x00\x00", enc.code(), "mov rax, 0x10");

    //     try enc.encode(.{ .tag = .mov, .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.mem(.dword, .{
    //         .base = .r11,
    //         .disp = 0,
    //     }), 0x10, 32) });
    //     try expectEqualHexStrings("\x41\xc7\x03\x10\x00\x00\x00", enc.code(), "mov dword ptr [r11], 0x10");

    //     try enc.encode(.{ .tag = .add, .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.mem(.dword, .{
    //         .base = .rdx,
    //         .disp = -8,
    //     }), 0x10, 32) });
    //     try expectEqualHexStrings("\x81\x42\xF8\x10\x00\x00\x00", enc.code(), "add dword ptr [rdx - 8], 0x10");

    //     try enc.encode(.{ .tag = .sub, .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.mem(.dword, .{
    //         .base = .r11,
    //         .disp = 0x10000000,
    //     }), 0x10, 32) });
    //     try expectEqualHexStrings(
    //         "\x41\x81\xab\x00\x00\x00\x10\x10\x00\x00\x00",
    //         enc.code(),
    //         "sub dword ptr [r11 + 0x10000000], 0x10",
    //     );

    //     try enc.encode(.{ .tag = .@"and", .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.mem(.dword, .{
    //         .base = .ds,
    //         .disp = 0x10000000,
    //     }), 0x10, 32) });
    //     try expectEqualHexStrings(
    //         "\x81\x24\x25\x00\x00\x00\x10\x10\x00\x00\x00",
    //         enc.code(),
    //         "and dword ptr [ds:0x10000000], 0x10",
    //     );

    //     try enc.encode(.{ .tag = .@"and", .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.mem(.dword, .{
    //         .base = .es,
    //         .disp = 0x10000000,
    //     }), 0x10, 32) });
    //     try expectEqualHexStrings(
    //         "\x26\x81\x24\x25\x00\x00\x00\x10\x10\x00\x00\x00",
    //         enc.code(),
    //         "and dword ptr [ds:0x10000000], 0x10",
    //     );

    //     try enc.encode(.{ .tag = .@"and", .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.mem(.dword, .{
    //         .base = .r12,
    //         .disp = 0x10000000,
    //     }), 0x10, 32) });
    //     try expectEqualHexStrings(
    //         "\x41\x81\xA4\x24\x00\x00\x00\x10\x10\x00\x00\x00",
    //         enc.code(),
    //         "and dword ptr [r12 + 0x10000000], 0x10",
    //     );

    //     try enc.encode(.{ .tag = .mov, .enc = .mi, .data = Instruction.Data.mi(
    //         RegisterOrMemory.rip(.qword, 0x10),
    //         0x10,
    //         32,
    //     ) });
    //     try expectEqualHexStrings(
    //         "\x48\xC7\x05\x10\x00\x00\x00\x10\x00\x00\x00",
    //         enc.code(),
    //         "mov QWORD PTR [rip + 0x10], 0x10",
    //     );

    //     try enc.encode(.{ .tag = .mov, .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.mem(.qword, .{
    //         .base = .rbp,
    //         .disp = -8,
    //     }), 0x10, 32) });
    //     try expectEqualHexStrings("\x48\xc7\x45\xf8\x10\x00\x00\x00", enc.code(), "mov QWORD PTR [rbp - 8], 0x10");

    //     try enc.encode(.{ .tag = .mov, .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.mem(.word, .{
    //         .base = .rbp,
    //         .disp = -2,
    //     }), @bitCast(u32, @as(i32, -16)), 16) });
    //     try expectEqualHexStrings("\x66\xC7\x45\xFE\xF0\xFF", enc.code(), "mov word ptr [rbp - 2], -16");

    //     try enc.encode(.{ .tag = .mov, .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.mem(.byte, .{
    //         .base = .rbp,
    //         .disp = -1,
    //     }), 0x10, 8) });
    //     try expectEqualHexStrings("\xC6\x45\xFF\x10", enc.code(), "mov BYTE PTR [rbp - 1], 0x10");

    //     try enc.encode(.{ .tag = .mov, .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.mem(.qword, .{
    //         .base = .ds,
    //         .disp = 0x10000000,
    //         .scale_index = .{
    //             .scale = 1,
    //             .index = .rcx,
    //         },
    //     }), 0x10, 32) });
    //     try expectEqualHexStrings(
    //         "\x48\xC7\x04\x4D\x00\x00\x00\x10\x10\x00\x00\x00",
    //         enc.code(),
    //         "mov QWORD PTR [rcx*2 + 0x10000000], 0x10",
    //     );

    //     try enc.encode(.{ .tag = .add, .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.reg(.rax), 0x10, 8) });
    //     try expectEqualHexStrings("\x48\x83\xC0\x10", enc.code(), "add rax, 0x10");

    //     try enc.encode(.{ .tag = .add, .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.mem(.qword, .{
    //         .base = .rbp,
    //         .disp = -0x10,
    //     }), @bitCast(u32, @as(i32, -0x10)), 8) });
    //     try expectEqualHexStrings("\x48\x83\x45\xF0\xF0", enc.code(), "add QWORD PTR [rbp - 0x10], -0x10");

    //     try enc.encode(.{ .tag = .adc, .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.mem(.byte, .{
    //         .base = .rbp,
    //         .disp = -0x10,
    //     }), 0x10, 8) });
    //     try expectEqualHexStrings("\x80\x55\xF0\x10", enc.code(), "adc BYTE PTR [rbp - 0x10], 0x10");

    //     try enc.encode(.{ .tag = .adc, .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.mem(.byte, .{
    //         .base = .rbp,
    //         .disp = -0x10,
    //     }), 0x10, 8) });
    //     try expectEqualHexStrings("\x80\x55\xF0\x10", enc.code(), "adc BYTE PTR [rbp - 0x10], 0x10");
}

test "lower RM encoding" {
    var enc = TestEncode{};

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .reg = .rax }, .op2 = .{ .mem = Memory.mem(.qword, .{
        .base = .r11,
        .disp = 0,
    }) } });
    try expectEqualHexStrings("\x49\x8b\x03", enc.code(), "mov rax, QWORD PTR [r11]");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .reg = .rbx }, .op2 = .{ .mem = Memory.mem(.qword, .{
        .base = .ds,
        .disp = 0x10,
    }) } });
    try expectEqualHexStrings("\x48\x8B\x1C\x25\x10\x00\x00\x00", enc.code(), "mov rbx, QWORD PTR ds:0x10");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .reg = .rax }, .op2 = .{ .mem = Memory.mem(.qword, .{
        .base = .rbp,
        .disp = -4,
    }) } });
    try expectEqualHexStrings("\x48\x8B\x45\xFC", enc.code(), "mov rax, QWORD PTR [rbp - 4]");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .reg = .rax }, .op2 = .{ .mem = Memory.mem(.qword, .{
        .base = .rbp,
        .scale_index = .{
            .scale = 0,
            .index = .rcx,
        },
        .disp = -8,
    }) } });
    try expectEqualHexStrings("\x48\x8B\x44\x0D\xF8", enc.code(), "mov rax, QWORD PTR [rbp + rcx*1 - 8]");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .reg = .eax }, .op2 = .{ .mem = Memory.mem(.dword, .{
        .base = .rbp,
        .scale_index = .{
            .scale = 2,
            .index = .rdx,
        },
        .disp = -4,
    }) } });
    try expectEqualHexStrings("\x8B\x44\x95\xFC", enc.code(), "mov eax, dword ptr [rbp + rdx*4 - 4]");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .reg = .rax }, .op2 = .{ .mem = Memory.mem(.qword, .{
        .base = .rbp,
        .scale_index = .{
            .scale = 3,
            .index = .rcx,
        },
        .disp = -8,
    }) } });
    try expectEqualHexStrings("\x48\x8B\x44\xCD\xF8", enc.code(), "mov rax, QWORD PTR [rbp + rcx*8 - 8]");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .reg = .r8b }, .op2 = .{ .mem = Memory.mem(.byte, .{
        .base = .rsi,
        .scale_index = .{
            .scale = 0,
            .index = .rcx,
        },
        .disp = -24,
    }) } });
    try expectEqualHexStrings("\x44\x8A\x44\x0E\xE8", enc.code(), "mov r8b, BYTE PTR [rsi + rcx*1 - 24]");

    try enc.encode(.{ .mnemonic = .movsx, .op1 = .{ .reg = .eax }, .op2 = .{ .reg = .bx } });
    try expectEqualHexStrings("\x0F\xBF\xC3", enc.code(), "movsx eax, bx");

    try enc.encode(.{ .mnemonic = .movsx, .op1 = .{ .reg = .eax }, .op2 = .{ .reg = .bl } });
    try expectEqualHexStrings("\x0F\xBE\xC3", enc.code(), "movsx eax, bl");

    try enc.encode(.{ .mnemonic = .movsx, .op1 = .{ .reg = .ax }, .op2 = .{ .reg = .bl } });
    try expectEqualHexStrings("\x66\x0F\xBE\xC3", enc.code(), "movsx ax, bl");

    try enc.encode(.{ .mnemonic = .movsx, .op1 = .{ .reg = .eax }, .op2 = .{ .mem = Memory.mem(.word, .{
        .base = .rbp,
        .disp = 0,
    }) } });
    try expectEqualHexStrings("\x0F\xBF\x45\x00", enc.code(), "movsx eax, BYTE PTR [rbp]");

    try enc.encode(.{ .mnemonic = .movsx, .op1 = .{ .reg = .eax }, .op2 = .{ .mem = Memory.mem(.byte, .{
        .base = null,
        .scale_index = .{
            .index = .rax,
            .scale = 1,
        },
        .disp = 0,
    }) } });
    try expectEqualHexStrings("\x0F\xBE\x04\x45\x00\x00\x00\x00", enc.code(), "movsx eax, BYTE PTR [rax * 2]");

    try enc.encode(.{ .mnemonic = .movsx, .op1 = .{ .reg = .ax }, .op2 = .{ .mem = Memory.rip(.byte, 0x10) } });
    try expectEqualHexStrings("\x66\x0F\xBE\x05\x10\x00\x00\x00", enc.code(), "movsx ax, BYTE PTR [rip + 0x10]");

    try enc.encode(.{ .mnemonic = .movsx, .op1 = .{ .reg = .rax }, .op2 = .{ .reg = .bx } });
    try expectEqualHexStrings("\x48\x0F\xBF\xC3", enc.code(), "movsx rax, bx");

    try enc.encode(.{ .mnemonic = .movsxd, .op1 = .{ .reg = .rax }, .op2 = .{ .reg = .ebx } });
    try expectEqualHexStrings("\x48\x63\xC3", enc.code(), "movsxd rax, ebx");

    try enc.encode(.{ .mnemonic = .lea, .op1 = .{ .reg = .rax }, .op2 = .{ .mem = Memory.rip(.qword, 0x10) } });
    try expectEqualHexStrings("\x48\x8D\x05\x10\x00\x00\x00", enc.code(), "lea rax, QWORD PTR [rip + 0x10]");

    try enc.encode(.{ .mnemonic = .lea, .op1 = .{ .reg = .rax }, .op2 = .{ .mem = Memory.rip(.dword, 0x10) } });
    try expectEqualHexStrings("\x48\x8D\x05\x10\x00\x00\x00", enc.code(), "lea rax, DWORD PTR [rip + 0x10]");

    try enc.encode(.{ .mnemonic = .lea, .op1 = .{ .reg = .eax }, .op2 = .{ .mem = Memory.rip(.dword, 0x10) } });
    try expectEqualHexStrings("\x8D\x05\x10\x00\x00\x00", enc.code(), "lea eax, DWORD PTR [rip + 0x10]");

    try enc.encode(.{ .mnemonic = .lea, .op1 = .{ .reg = .eax }, .op2 = .{ .mem = Memory.rip(.word, 0x10) } });
    try expectEqualHexStrings("\x8D\x05\x10\x00\x00\x00", enc.code(), "lea eax, WORD PTR [rip + 0x10]");

    try enc.encode(.{ .mnemonic = .lea, .op1 = .{ .reg = .ax }, .op2 = .{ .mem = Memory.rip(.byte, 0x10) } });
    try expectEqualHexStrings("\x66\x8D\x05\x10\x00\x00\x00", enc.code(), "lea ax, BYTE PTR [rip + 0x10]");

    //     try enc.encode(.{ .tag = .lea, .enc = .rm, .data = Instruction.Data.rm(.rsi, RegisterOrMemory.mem(.qword, .{
    //         .base = .rbp,
    //         .scale_index = .{
    //             .scale = 0,
    //             .index = .rcx,
    //         },
    //         .disp = 0,
    //     })) });
    //     try expectEqualHexStrings("\x48\x8D\x74\x0D\x00", enc.code(), "lea rsi, QWORD PTR [rbp + rcx*1 + 0]");

    //     try enc.encode(.{ .tag = .add, .enc = .rm, .data = Instruction.Data.rm(.r11, RegisterOrMemory.mem(.qword, .{
    //         .base = .ds,
    //         .disp = 0x10000000,
    //     })) });
    //     try expectEqualHexStrings("\x4C\x03\x1C\x25\x00\x00\x00\x10", enc.code(), "add r11, QWORD PTR ds:0x10000000");

    //     try enc.encode(.{ .tag = .add, .enc = .rm, .data = Instruction.Data.rm(.r12b, RegisterOrMemory.mem(.byte, .{
    //         .base = .ds,
    //         .disp = 0x10000000,
    //     })) });
    //     try expectEqualHexStrings("\x44\x02\x24\x25\x00\x00\x00\x10", enc.code(), "add r11b, BYTE PTR ds:0x10000000");

    //     try enc.encode(.{ .tag = .add, .enc = .rm, .data = Instruction.Data.rm(.r12b, RegisterOrMemory.mem(.byte, .{
    //         .base = .fs,
    //         .disp = 0x10000000,
    //     })) });
    //     try expectEqualHexStrings("\x64\x44\x02\x24\x25\x00\x00\x00\x10", enc.code(), "add r11b, BYTE PTR fs:0x10000000");

    //     try enc.encode(.{ .tag = .sub, .enc = .rm, .data = Instruction.Data.rm(.r11, RegisterOrMemory.mem(.qword, .{
    //         .base = .r13,
    //         .disp = 0x10000000,
    //     })) });
    //     try expectEqualHexStrings("\x4D\x2B\x9D\x00\x00\x00\x10", enc.code(), "sub r11, QWORD PTR [r13 + 0x10000000]");

    //     try enc.encode(.{ .tag = .sub, .enc = .rm, .data = Instruction.Data.rm(.r11, RegisterOrMemory.mem(.qword, .{
    //         .base = .r12,
    //         .disp = 0x10000000,
    //     })) });
    //     try expectEqualHexStrings("\x4D\x2B\x9C\x24\x00\x00\x00\x10", enc.code(), "sub r11, QWORD PTR [r12 + 0x10000000]");

}

test "lower MR encoding" {
    var enc = TestEncode{};

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .reg = .rax }, .op2 = .{ .reg = .rbx } });
    try expectEqualHexStrings("\x48\x89\xD8", enc.code(), "mov rax, rbx");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .mem = Memory.mem(.qword, .{
        .base = .rbp,
        .disp = -4,
    }) }, .op2 = .{ .reg = .r11 } });
    try expectEqualHexStrings("\x4c\x89\x5d\xfc", enc.code(), "mov QWORD PTR [rbp - 4], r11");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .mem = Memory.rip(.qword, 0x10) }, .op2 = .{ .reg = .r12 } });
    try expectEqualHexStrings("\x4C\x89\x25\x10\x00\x00\x00", enc.code(), "mov QWORD PTR [rip + 0x10], r12");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .mem = Memory.mem(.qword, .{
        .base = .r11,
        .scale_index = .{
            .scale = 1,
            .index = .r12,
        },
        .disp = 0x10,
    }) }, .op2 = .{ .reg = .r13 } });
    try expectEqualHexStrings("\x4F\x89\x6C\x63\x10", enc.code(), "mov QWORD PTR [r11 + 2 * r12 + 0x10], r13");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .mem = Memory.rip(.word, -0x10) }, .op2 = .{ .reg = .r12w } });
    try expectEqualHexStrings("\x66\x44\x89\x25\xF0\xFF\xFF\xFF", enc.code(), "mov WORD PTR [rip - 0x10], r12w");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .mem = Memory.mem(.byte, .{
        .base = .r11,
        .scale_index = .{
            .scale = 1,
            .index = .r12,
        },
        .disp = 0x10,
    }) }, .op2 = .{ .reg = .r13b } });
    try expectEqualHexStrings("\x47\x88\x6C\x63\x10", enc.code(), "mov BYTE PTR [r11 + 2 * r12 + 0x10], r13b");

    //     try enc.encode(.{ .tag = .add, .enc = .mr, .data = Instruction.Data.mr(RegisterOrMemory.mem(.byte, .{
    //         .base = .ds,
    //         .disp = 0x10000000,
    //     }), .r12b) });
    //     try expectEqualHexStrings("\x44\x00\x24\x25\x00\x00\x00\x10", enc.code(), "add BYTE PTR ds:0x10000000, r12b");

    //     try enc.encode(.{ .tag = .add, .enc = .mr, .data = Instruction.Data.mr(RegisterOrMemory.mem(.dword, .{
    //         .base = .ds,
    //         .disp = 0x10000000,
    //     }), .r12d) });
    //     try expectEqualHexStrings("\x44\x01\x24\x25\x00\x00\x00\x10", enc.code(), "add dword ptr [ds:0x10000000], r12d");

    //     try enc.encode(.{ .tag = .add, .enc = .mr, .data = Instruction.Data.mr(RegisterOrMemory.mem(.dword, .{
    //         .base = .gs,
    //         .disp = 0x10000000,
    //     }), .r12d) });
    //     try expectEqualHexStrings("\x65\x44\x01\x24\x25\x00\x00\x00\x10", enc.code(), "add dword ptr [gs:0x10000000], r12d");

    //     try enc.encode(.{ .tag = .sub, .enc = .mr, .data = Instruction.Data.mr(RegisterOrMemory.mem(.qword, .{
    //         .base = .r11,
    //         .disp = 0x10000000,
    //     }), .r12) });
    //     try expectEqualHexStrings("\x4D\x29\xA3\x00\x00\x00\x10", enc.code(), "sub QWORD PTR [r11 + 0x10000000], r12");

}

test "lower M encoding" {
    var enc = TestEncode{};

    try enc.encode(.{ .mnemonic = .call, .op1 = .{ .reg = .r12 } });
    try expectEqualHexStrings("\x41\xFF\xD4", enc.code(), "call r12");

    try enc.encode(.{ .mnemonic = .call, .op1 = .{ .mem = Memory.mem(.qword, .{
        .base = .r12,
        .disp = 0,
    }) } });
    try expectEqualHexStrings("\x41\xFF\x14\x24", enc.code(), "call QWORD PTR [r12]");

    try enc.encode(.{ .mnemonic = .call, .op1 = .{ .mem = Memory.mem(.qword, .{
        .base = null,
        .scale_index = .{
            .index = .r11,
            .scale = 1,
        },
        .disp = 0,
    }) } });
    try expectEqualHexStrings("\x42\xFF\x14\x5D\x00\x00\x00\x00", enc.code(), "call QWORD PTR [r11 * 2]");

    try enc.encode(.{ .mnemonic = .call, .op1 = .{ .mem = Memory.mem(.qword, .{
        .base = null,
        .scale_index = .{
            .index = .r12,
            .scale = 1,
        },
        .disp = 0,
    }) } });
    try expectEqualHexStrings("\x42\xFF\x14\x65\x00\x00\x00\x00", enc.code(), "call QWORD PTR [r12 * 2]");

    try enc.encode(.{ .mnemonic = .call, .op1 = .{ .mem = Memory.mem(.qword, .{
        .base = .gs,
        .disp = 0,
    }) } });
    try expectEqualHexStrings("\x65\xFF\x14\x25\x00\x00\x00\x00", enc.code(), "call gs:0x0");

    //     try enc.encode(.{ .tag = .call, .enc = .m, .data = Instruction.Data.m(RegisterOrMemory.mem(.qword, .{
    //         .base = null,
    //         .disp = 0,
    //     })) });
    //     try expectEqualHexStrings("\xE8\x00\x00\x00\x00", enc.code(), "call 0x0");

    try enc.encode(.{ .mnemonic = .push, .op1 = .{ .mem = Memory.mem(.qword, .{
        .base = .rbp,
        .disp = 0,
    }) } });
    try expectEqualHexStrings("\xFF\x75\x00", enc.code(), "push QWORD PTR [rbp]");

    try enc.encode(.{ .mnemonic = .push, .op1 = .{ .mem = Memory.mem(.word, .{
        .base = .rbp,
        .disp = 0,
    }) } });
    try expectEqualHexStrings("\x66\xFF\x75\x00", enc.code(), "push QWORD PTR [rbp]");

    try enc.encode(.{ .mnemonic = .pop, .op1 = .{ .mem = Memory.rip(.qword, 0) } });
    try expectEqualHexStrings("\x8F\x05\x00\x00\x00\x00", enc.code(), "pop QWORD PTR [rip]");

    try enc.encode(.{ .mnemonic = .pop, .op1 = .{ .mem = Memory.rip(.word, 0) } });
    try expectEqualHexStrings("\x66\x8F\x05\x00\x00\x00\x00", enc.code(), "pop WORD PTR [rbp]");
}

// test "lower O encoding" {
//     var enc = TestEncode{};

//     try enc.encode(.{ .tag = .push, .enc = .o, .data = Instruction.Data.o(.rax) });
//     try expectEqualHexStrings("\x50", enc.code(), "push rax");

//     try enc.encode(.{ .tag = .push, .enc = .o, .data = Instruction.Data.o(.r12w) });
//     try expectEqualHexStrings("\x66\x41\x54", enc.code(), "push r12w");

//     try enc.encode(.{ .tag = .pop, .enc = .o, .data = Instruction.Data.o(.r12) });
//     try expectEqualHexStrings("\x41\x5c", enc.code(), "pop r12");
// }

test "lower OI encoding" {
    var enc = TestEncode{};

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .reg = .rax }, .op2 = .{ .imm = 0x1000000000000000 } });
    try expectEqualHexStrings("\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x10", enc.code(), "movabs rax, 0x1000000000000000");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .reg = .r11 }, .op2 = .{ .imm = 0x1000000000000000 } });
    try expectEqualHexStrings("\x49\xBB\x00\x00\x00\x00\x00\x00\x00\x10", enc.code(), "movabs r11, 0x1000000000000000");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .reg = .r11d }, .op2 = .{ .imm = 0x10000000 } });
    try expectEqualHexStrings("\x41\xBB\x00\x00\x00\x10", enc.code(), "mov r11d, 0x10000000");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .reg = .r11w }, .op2 = .{ .imm = 0x1000 } });
    try expectEqualHexStrings("\x66\x41\xBB\x00\x10", enc.code(), "mov r11w, 0x1000");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .reg = .r11b }, .op2 = .{ .imm = 0x10 } });
    try expectEqualHexStrings("\x41\xB3\x10", enc.code(), "mov r11b, 0x10");
}

test "lower FD/TD encoding" {
    var enc = TestEncode{};

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .reg = .rax }, .op2 = .{ .moffs = Moffs.moffs(.cs, 0x10) } });
    try expectEqualHexStrings("\x2E\x48\xA1\x10\x00\x00\x00\x00\x00\x00\x00", enc.code(), "movabs rax, cs:0x10");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .reg = .eax }, .op2 = .{ .moffs = Moffs.moffs(.fs, 0x10) } });
    try expectEqualHexStrings("\x64\xA1\x10\x00\x00\x00\x00\x00\x00\x00", enc.code(), "movabs eax, fs:0x10");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .reg = .ax }, .op2 = .{ .moffs = Moffs.moffs(.gs, 0x10) } });
    try expectEqualHexStrings("\x65\x66\xA1\x10\x00\x00\x00\x00\x00\x00\x00", enc.code(), "movabs ax, gs:0x10");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .reg = .al }, .op2 = .{ .moffs = Moffs.moffs(.ds, 0x10) } });
    try expectEqualHexStrings("\xA0\x10\x00\x00\x00\x00\x00\x00\x00", enc.code(), "movabs al, ds:0x10");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .moffs = Moffs.moffs(.cs, 0x10) }, .op2 = .{ .reg = .rax } });
    try expectEqualHexStrings("\x2E\x48\xA3\x10\x00\x00\x00\x00\x00\x00\x00", enc.code(), "movabs cs:0x10, rax");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .moffs = Moffs.moffs(.fs, 0x10) }, .op2 = .{ .reg = .eax } });
    try expectEqualHexStrings("\x64\xA3\x10\x00\x00\x00\x00\x00\x00\x00", enc.code(), "movabs fs:0x10, eax");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .moffs = Moffs.moffs(.gs, 0x10) }, .op2 = .{ .reg = .ax } });
    try expectEqualHexStrings("\x65\x66\xA3\x10\x00\x00\x00\x00\x00\x00\x00", enc.code(), "movabs gs:0x10, ax");

    try enc.encode(.{ .mnemonic = .mov, .op1 = .{ .moffs = Moffs.moffs(.ds, 0x10) }, .op2 = .{ .reg = .al } });
    try expectEqualHexStrings("\xA2\x10\x00\x00\x00\x00\x00\x00\x00", enc.code(), "movabs ds:0x10, al");
}

test "lower NP encoding" {
    var enc = TestEncode{};

    try enc.encode(.{ .mnemonic = .int3 });
    try expectEqualHexStrings("\xCC", enc.code(), "int3");

    try enc.encode(.{ .mnemonic = .nop });
    try expectEqualHexStrings("\x90", enc.code(), "nop");

    try enc.encode(.{ .mnemonic = .ret });
    try expectEqualHexStrings("\xC3", enc.code(), "ret");

    try enc.encode(.{ .mnemonic = .syscall });
    try expectEqualHexStrings("\x0f\x05", enc.code(), "syscall");
}

test "invalid lowering" {
    try expectError(.{ .mnemonic = .call, .op1 = .{ .reg = .eax } });
    try expectError(.{ .mnemonic = .call, .op1 = .{ .reg = .ax } });
    try expectError(.{ .mnemonic = .call, .op1 = .{ .reg = .al } });
    try expectError(.{ .mnemonic = .call, .op1 = .{ .mem = Memory.rip(.dword, 0) } });
    try expectError(.{ .mnemonic = .call, .op1 = .{ .mem = Memory.rip(.word, 0) } });
    try expectError(.{ .mnemonic = .call, .op1 = .{ .mem = Memory.rip(.byte, 0) } });
    try expectError(.{ .mnemonic = .mov, .op1 = .{ .mem = Memory.rip(.word, 0x10) }, .op2 = .{ .reg = .r12 } });
    try expectError(.{ .mnemonic = .lea, .op1 = .{ .reg = .rax }, .op2 = .{ .reg = .rbx } });
    try expectError(.{ .mnemonic = .lea, .op1 = .{ .reg = .al }, .op2 = .{ .mem = Memory.rip(.byte, 0) } });
}
