const std = @import("std");
const assert = std.debug.assert;
const mem = std.mem;
const testing = std.testing;

const dis_x86_64 = @import("dis_x86_64.zig");
const Disassembler = dis_x86_64.Disassembler;
const Instruction = dis_x86_64.Instruction;
const RegisterOrMemory = dis_x86_64.RegisterOrMemory;

// Decoder tests
// zig fmt: on

test "disassemble" {
    var disassembler = Disassembler.init(&.{
        // zig fmt: off
        0x40, 0xb7, 0x10,                                           // mov dil, 0x10
        0x49, 0xbc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, // mov r12, 0x1000000000000000
        0xb8, 0x00, 0x00, 0x00, 0x10,                               // mov eax, 0x10000000 
        0x48, 0x8b, 0xd8,                                           // mov rbx, rax
        0x4d, 0x8b, 0xdc,                                           // mov r11, r12
        0x49, 0x8b, 0xd4,                                           // mov rdx, r12
        0x4d, 0x89, 0xdc,                                           // mov r12, r11
        0x49, 0x89, 0xd4,                                           // mov r12, rdx
        0x4c, 0x8b, 0x65, 0xf0,                                     // mov r12, qword ptr [rbp - 0x10] 
        0x48, 0x8b, 0x85, 0x00, 0xf0, 0xff, 0xff,                   // mov rax, qword ptr [rbp - 0x1000]
        0x48, 0x8b, 0x1d, 0x00, 0x00, 0x00, 0x00,                   // mov rbx, qword ptr [rip + 0x0]
        0x48, 0x8b, 0x18,                                           // mov rbx, qword ptr [rax]
        // zig fmt: on
    });

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .oi);
        try testing.expect(inst.data.oi.reg == .bh);
        try testing.expect(inst.data.oi.imm == 0x10);
    }

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .oi);
        try testing.expect(inst.data.oi.reg == .r12);
        try testing.expect(inst.data.oi.imm == 0x1000000000000000);
    }

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .oi);
        try testing.expect(inst.data.oi.reg == .eax);
        try testing.expect(inst.data.oi.imm == 0x10000000);
    }

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .rm);
        try testing.expect(inst.data.rm.reg == .rbx);
        try testing.expect(inst.data.rm.reg_or_mem.reg == .rax);
    }

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .rm);
        try testing.expect(inst.data.rm.reg == .r11);
        try testing.expect(inst.data.rm.reg_or_mem.reg == .r12);
    }

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .rm);
        try testing.expect(inst.data.rm.reg == .rdx);
        try testing.expect(inst.data.rm.reg_or_mem.reg == .r12);
    }

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .mr);
        try testing.expect(inst.data.mr.reg_or_mem.reg == .r12);
        try testing.expect(inst.data.mr.reg == .r11);
    }

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .mr);
        try testing.expect(inst.data.mr.reg_or_mem.reg == .r12);
        try testing.expect(inst.data.mr.reg == .rdx);
    }

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .rm);
        try testing.expect(inst.data.rm.reg == .r12);
        try testing.expect(inst.data.rm.reg_or_mem.mem.ptr_size == .qword);
        try testing.expect(inst.data.rm.reg_or_mem.mem.scale_index == null);
        try testing.expect(inst.data.rm.reg_or_mem.mem.base.reg == .rbp);
        try testing.expect(@intCast(i8, @bitCast(i32, inst.data.rm.reg_or_mem.mem.disp.?)) == -0x10);
    }

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .rm);
        try testing.expect(inst.data.rm.reg == .rax);
        try testing.expect(inst.data.rm.reg_or_mem.mem.ptr_size == .qword);
        try testing.expect(inst.data.rm.reg_or_mem.mem.scale_index == null);
        try testing.expect(inst.data.rm.reg_or_mem.mem.base.reg == .rbp);
        try testing.expect(@bitCast(i32, inst.data.rm.reg_or_mem.mem.disp.?) == -0x1000);
    }

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .rm);
        try testing.expect(inst.data.rm.reg == .rbx);
        try testing.expect(inst.data.rm.reg_or_mem.mem.ptr_size == .qword);
        try testing.expect(inst.data.rm.reg_or_mem.mem.scale_index == null);
        try testing.expect(inst.data.rm.reg_or_mem.mem.base == .rip);
        try testing.expect(@bitCast(i32, inst.data.rm.reg_or_mem.mem.disp.?) == 0x0);
    }

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .rm);
        try testing.expect(inst.data.rm.reg == .rbx);
        try testing.expect(inst.data.rm.reg_or_mem.mem.ptr_size == .qword);
        try testing.expect(inst.data.rm.reg_or_mem.mem.scale_index == null);
        try testing.expect(inst.data.rm.reg_or_mem.mem.base.reg == .rax);
        try testing.expect(inst.data.rm.reg_or_mem.mem.disp == null);
    }
}

test "disassemble - mnemonic" {
    const gpa = testing.allocator;
    var disassembler = Disassembler.init(&.{
        // zig fmt: off
        0x48, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x41, 0xbc, 0xf0, 0xff, 0xff, 0xff,
        0x4c, 0x8b, 0x65, 0xf0,
        0x48, 0x8b, 0x85, 0x00, 0xf0, 0xff, 0xff,
        0x48, 0x8b, 0x18,
        0xc6, 0x45, 0xf0, 0x10,
        0x49, 0xc7, 0x43, 0xf0, 0x10, 0x00, 0x00, 0x00,
        0x49, 0x89, 0x43, 0xf0,
        0x48, 0x8d, 0x45, 0xf0,
        0x41, 0x8d, 0x43, 0x10,
        0x4c, 0x8d, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x03, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x83, 0xc0, 0x10,
        0x48, 0x83, 0x45, 0xf0, 0xf0,
        0x80, 0x55, 0xf0, 0x10,
        0x48, 0x83, 0x60, 0x10, 0x08,
        0x48, 0x83, 0x4d, 0x10, 0x0f,
        0x49, 0x83, 0xdb, 0x08,
        // zig fmt: on
    });

    var buf = std.ArrayList(u8).init(gpa);
    defer buf.deinit();

    while (try disassembler.next()) |inst| {
        try inst.fmtPrint(buf.writer());
        try buf.append('\n');
    }

    try testing.expectEqualStrings(
        \\movabs rax, 0x10
        \\mov r12d, -0x10
        \\mov r12, qword ptr [rbp - 0x10]
        \\mov rax, qword ptr [rbp - 0x1000]
        \\mov rbx, qword ptr [rax]
        \\mov byte ptr [rbp - 0x10], 0x10
        \\mov qword ptr [r11 - 0x10], 0x10
        \\mov qword ptr [r11 - 0x10], rax
        \\lea rax, qword ptr [rbp - 0x10]
        \\lea eax, dword ptr [r11 + 0x10]
        \\lea r12, qword ptr [rip + 0x0]
        \\add rax, qword ptr [rip + 0x0]
        \\add rax, 0x10
        \\add qword ptr [rbp - 0x10], -0x10
        \\adc byte ptr [rbp - 0x10], 0x10
        \\and qword ptr [rax + 0x10], 0x8
        \\or qword ptr [rbp + 0x10], 0xf
        \\sbb r11, 0x8
        \\
    , buf.items);
}

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

const TestEncode = struct {
    buffer: [32]u8 = undefined,
    index: usize = 0,

    fn encode(enc: *TestEncode, inst: Instruction) !void {
        var stream = std.io.fixedBufferStream(&enc.buffer);
        var count_writer = std.io.countingWriter(stream.writer());
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

    const inst = Instruction{
        .tag = .mov,
        .enc = .mi,
        .data = Instruction.Data.mi(RegisterOrMemory.reg(.rbx), 0x4),
    };
    try inst.encode(buf.writer());
    try testing.expectEqualSlices(u8, &.{ 0x48, 0xc7, 0xc3, 0x4, 0x0, 0x0, 0x0 }, buf.items);
}

test "lower MI encoding" {
    var enc = TestEncode{};

    try enc.encode(.{ .tag = .mov, .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.reg(.rax), 0x10) });
    try expectEqualHexStrings("\x48\xc7\xc0\x10\x00\x00\x00", enc.code(), "mov rax, 0x10");

    try enc.encode(.{ .tag = .mov, .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.mem(.{
        .ptr_size = .dword,
        .base = .{ .reg = .r11 },
    }), 0x10) });
    try expectEqualHexStrings("\x41\xc7\x03\x10\x00\x00\x00", enc.code(), "mov dword ptr [r11], 0x10");

    try enc.encode(.{ .tag = .mov, .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.mem(.{
        .ptr_size = .dword,
        .base = .{ .reg = .r11 },
        .disp = 0,
    }), 0x10) });
    try expectEqualHexStrings("\x41\xc7\x43\x00\x10\x00\x00\x00", enc.code(), "mov dword ptr [r11 + 0], 0x10");

    try enc.encode(.{ .tag = .add, .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.mem(.{
        .ptr_size = .dword,
        .base = .{ .reg = .rdx },
        .disp = -8,
    }), 0x10) });
    try expectEqualHexStrings("\x81\x42\xF8\x10\x00\x00\x00", enc.code(), "add dword ptr [rdx - 8], 0x10");

    // try lowerToMiEnc(.sub, RegisterOrMemory.mem(.dword_ptr, .{
    //     .disp = 0x10000000,
    //     .base = .r11,
    // }), 0x10, emit.code());
    // try expectEqualHexStrings(
    //     "\x41\x81\xab\x00\x00\x00\x10\x10\x00\x00\x00",
    //     emit.lowered(),
    //     "sub dword ptr [r11 + 0x10000000], 0x10",
    // );
    // try lowerToMiEnc(.@"and", RegisterOrMemory.mem(.dword_ptr, .{ .disp = 0x10000000 }), 0x10, emit.code());
    // try expectEqualHexStrings(
    //     "\x81\x24\x25\x00\x00\x00\x10\x10\x00\x00\x00",
    //     emit.lowered(),
    //     "and dword ptr [ds:0x10000000], 0x10",
    // );
    // try lowerToMiEnc(.@"and", RegisterOrMemory.mem(.dword_ptr, .{
    //     .disp = 0x10000000,
    //     .base = .r12,
    // }), 0x10, emit.code());
    // try expectEqualHexStrings(
    //     "\x41\x81\xA4\x24\x00\x00\x00\x10\x10\x00\x00\x00",
    //     emit.lowered(),
    //     "and dword ptr [r12 + 0x10000000], 0x10",
    // );

    try enc.encode(.{ .tag = .mov, .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.mem(.{
        .ptr_size = .qword,
        .base = .rip,
        .disp = 0x10,
    }), 0x10) });
    try expectEqualHexStrings(
        "\x48\xC7\x05\x10\x00\x00\x00\x10\x00\x00\x00",
        enc.code(),
        "mov qword ptr [rip + 0x10], 0x10",
    );

    try enc.encode(.{ .tag = .mov, .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.mem(.{
        .ptr_size = .qword,
        .base = .{ .reg = .rbp },
        .disp = -8,
    }), 0x10) });
    try expectEqualHexStrings("\x48\xc7\x45\xf8\x10\x00\x00\x00", enc.code(), "mov qword ptr [rbp - 8], 0x10");

    try enc.encode(.{ .tag = .mov, .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.mem(.{
        .ptr_size = .word,
        .base = .{ .reg = .rbp },
        .disp = -2,
    }), -16) });
    try expectEqualHexStrings("\x66\xC7\x45\xFE\xF0\xFF", enc.code(), "mov word ptr [rbp - 2], -16");

    try enc.encode(.{ .tag = .mov, .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.mem(.{
        .ptr_size = .byte,
        .base = .{ .reg = .rbp },
        .disp = -1,
    }), 0x10) });
    try expectEqualHexStrings("\xC6\x45\xFF\x10", enc.code(), "mov byte ptr [rbp - 1], 0x10");

    try enc.encode(.{ .tag = .mov, .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.mem(.{
        .ptr_size = .qword,
        .base = .seg,
        .disp = 0x10000000,
        .scale_index = .{
            .scale = 1,
            .index = .rcx,
        },
    }), 0x10) });
    try expectEqualHexStrings(
        "\x48\xC7\x04\x4D\x00\x00\x00\x10\x10\x00\x00\x00",
        enc.code(),
        "mov qword ptr [rcx*2 + 0x10000000], 0x10",
    );

    try enc.encode(.{ .tag = .add, .enc = .mi8, .data = Instruction.Data.mi(RegisterOrMemory.reg(.rax), 0x10) });
    try expectEqualHexStrings("\x48\x83\xC0\x10", enc.code(), "add rax, 0x10");

    try enc.encode(.{ .tag = .add, .enc = .mi8, .data = Instruction.Data.mi(RegisterOrMemory.mem(.{
        .ptr_size = .qword,
        .base = .{ .reg = .rbp },
        .disp = -0x10,
    }), -0x10) });
    try expectEqualHexStrings("\x48\x83\x45\xF0\xF0", enc.code(), "add qword ptr [rbp - 0x10], -0x10");

    try enc.encode(.{ .tag = .adc, .enc = .mi8, .data = Instruction.Data.mi(RegisterOrMemory.mem(.{
        .ptr_size = .byte,
        .base = .{ .reg = .rbp },
        .disp = -0x10,
    }), 0x10) });
    try expectEqualHexStrings("\x80\x55\xF0\x10", enc.code(), "adc byte ptr [rbp - 0x10], 0x10");

    try enc.encode(.{ .tag = .adc, .enc = .mi, .data = Instruction.Data.mi(RegisterOrMemory.mem(.{
        .ptr_size = .byte,
        .base = .{ .reg = .rbp },
        .disp = -0x10,
    }), 0x10) });
    try expectEqualHexStrings("\x80\x55\xF0\x10", enc.code(), "adc byte ptr [rbp - 0x10], 0x10");
}

test "lower RM encoding" {
    var enc = TestEncode{};

    try enc.encode(.{ .tag = .mov, .enc = .rm, .data = Instruction.Data.rm(.rax, RegisterOrMemory.reg(.rbx)) });
    try expectEqualHexStrings("\x48\x8b\xc3", enc.code(), "mov rax, rbx");

    try enc.encode(.{ .tag = .mov, .enc = .rm, .data = Instruction.Data.rm(.rax, RegisterOrMemory.mem(.{
        .ptr_size = .qword,
        .base = .{ .reg = .r11 },
    })) });
    try expectEqualHexStrings("\x49\x8b\x03", enc.code(), "mov rax, qword ptr [r11]");

    try enc.encode(.{ .tag = .add, .enc = .rm, .data = Instruction.Data.rm(.r11, RegisterOrMemory.mem(.{
        .ptr_size = .qword,
        .base = .seg,
        .disp = 0x10000000,
    })) });
    try expectEqualHexStrings("\x4C\x03\x1C\x25\x00\x00\x00\x10", enc.code(), "add r11, qword ptr [ds:0x10000000]");

    try enc.encode(.{ .tag = .add, .enc = .rm, .data = Instruction.Data.rm(.r12b, RegisterOrMemory.mem(.{
        .ptr_size = .byte,
        .base = .seg,
        .disp = 0x10000000,
    })) });
    try expectEqualHexStrings("\x44\x02\x24\x25\x00\x00\x00\x10", enc.code(), "add r11b, byte ptr [ds:0x10000000]");

    // try lowerToRmEnc(.sub, .r11, RegisterOrMemory.mem(.qword_ptr, .{
    //     .disp = 0x10000000,
    //     .base = .r13,
    // }), emit.code());
    // try expectEqualHexStrings(
    //     "\x4D\x2B\x9D\x00\x00\x00\x10",
    //     emit.lowered(),
    //     "sub r11, qword ptr [r13 + 0x10000000]",
    // );
    // try lowerToRmEnc(.sub, .r11, RegisterOrMemory.mem(.qword_ptr, .{
    //     .disp = 0x10000000,
    //     .base = .r12,
    // }), emit.code());
    // try expectEqualHexStrings(
    //     "\x4D\x2B\x9C\x24\x00\x00\x00\x10",
    //     emit.lowered(),
    //     "sub r11, qword ptr [r12 + 0x10000000]",
    // );
    //

    try enc.encode(.{ .tag = .mov, .enc = .rm, .data = Instruction.Data.rm(.rax, RegisterOrMemory.mem(.{
        .ptr_size = .qword,
        .base = .{ .reg = .rbp },
        .disp = -4,
    })) });
    try expectEqualHexStrings("\x48\x8B\x45\xFC", enc.code(), "mov rax, qword ptr [rbp - 4]");

    try enc.encode(.{ .tag = .lea, .enc = .rm, .data = Instruction.Data.rm(.rax, RegisterOrMemory.mem(.{
        .ptr_size = .qword,
        .base = .rip,
        .disp = 0x10,
    })) });
    try expectEqualHexStrings("\x48\x8D\x05\x10\x00\x00\x00", enc.code(), "lea rax, [rip + 0x10]");

    try enc.encode(.{ .tag = .mov, .enc = .rm, .data = Instruction.Data.rm(.rax, RegisterOrMemory.mem(.{
        .ptr_size = .qword,
        .base = .{ .reg = .rbp },
        .scale_index = .{
            .scale = 0,
            .index = .rcx,
        },
        .disp = -8,
    })) });
    try expectEqualHexStrings("\x48\x8B\x44\x0D\xF8", enc.code(), "mov rax, qword ptr [rbp + rcx*1 - 8]");

    try enc.encode(.{ .tag = .mov, .enc = .rm, .data = Instruction.Data.rm(.eax, RegisterOrMemory.mem(.{
        .ptr_size = .dword,
        .base = .{ .reg = .rbp },
        .scale_index = .{
            .scale = 2,
            .index = .rdx,
        },
        .disp = -4,
    })) });
    try expectEqualHexStrings("\x8B\x44\x95\xFC", enc.code(), "mov eax, dword ptr [rbp + rdx*4 - 4]");

    try enc.encode(.{ .tag = .mov, .enc = .rm, .data = Instruction.Data.rm(.rax, RegisterOrMemory.mem(.{
        .ptr_size = .qword,
        .base = .{ .reg = .rbp },
        .scale_index = .{
            .scale = 3,
            .index = .rcx,
        },
        .disp = -8,
    })) });
    try expectEqualHexStrings("\x48\x8B\x44\xCD\xF8", enc.code(), "mov rax, qword ptr [rbp + rcx*8 - 8]");

    try enc.encode(.{ .tag = .mov, .enc = .rm, .data = Instruction.Data.rm(.r8b, RegisterOrMemory.mem(.{
        .ptr_size = .byte,
        .base = .{ .reg = .rsi },
        .scale_index = .{
            .scale = 0,
            .index = .rcx,
        },
        .disp = -24,
    })) });
    try expectEqualHexStrings("\x44\x8A\x44\x0E\xE8", enc.code(), "mov r8b, byte ptr [rsi + rcx*1 - 24]");

    try enc.encode(.{ .tag = .lea, .enc = .rm, .data = Instruction.Data.rm(.rsi, RegisterOrMemory.mem(.{
        .ptr_size = .qword,
        .base = .{ .reg = .rbp },
        .scale_index = .{
            .scale = 0,
            .index = .rcx,
        },
    })) });
    try expectEqualHexStrings("\x48\x8D\x74\x0D\x00", enc.code(), "lea rsi, qword ptr [rbp + rcx*1 + 0]");
}

test "lower MR encoding" {
    var enc = TestEncode{};

    try enc.encode(.{ .tag = .mov, .enc = .mr, .data = Instruction.Data.mr(RegisterOrMemory.reg(.rax), .rbx) });
    try expectEqualHexStrings("\x48\x89\xd8", enc.code(), "mov rax, rbx");

    try enc.encode(.{ .tag = .mov, .enc = .mr, .data = Instruction.Data.mr(RegisterOrMemory.mem(.{
        .ptr_size = .qword,
        .base = .{ .reg = .rbp },
        .disp = -4,
    }), .r11) });
    try expectEqualHexStrings("\x4c\x89\x5d\xfc", enc.code(), "mov qword ptr [rbp - 4], r11");

    try enc.encode(.{ .tag = .add, .enc = .mr, .data = Instruction.Data.mr(RegisterOrMemory.mem(.{
        .ptr_size = .byte,
        .base = .seg,
        .disp = 0x10000000,
    }), .r12b) });
    try expectEqualHexStrings("\x44\x00\x24\x25\x00\x00\x00\x10", enc.code(), "add byte ptr [ds:0x10000000], r12b");

    try enc.encode(.{ .tag = .add, .enc = .mr, .data = Instruction.Data.mr(RegisterOrMemory.mem(.{
        .ptr_size = .dword,
        .base = .seg,
        .disp = 0x10000000,
    }), .r12d) });
    try expectEqualHexStrings("\x44\x01\x24\x25\x00\x00\x00\x10", enc.code(), "add dword ptr [ds:0x10000000], r12d");

    // try lowerToMrEnc(.sub, RegisterOrMemory.mem(.qword_ptr, .{
    //     .disp = 0x10000000,
    //     .base = .r11,
    // }), .r12, emit.code());
    // try expectEqualHexStrings(
    //     "\x4D\x29\xA3\x00\x00\x00\x10",
    //     emit.lowered(),
    //     "sub qword ptr [r11 + 0x10000000], r12",
    // );

    try enc.encode(.{ .tag = .mov, .enc = .mr, .data = Instruction.Data.mr(RegisterOrMemory.mem(.{
        .ptr_size = .qword,
        .base = .rip,
        .disp = 0x10,
    }), .r12) });
    try expectEqualHexStrings("\x4C\x89\x25\x10\x00\x00\x00", enc.code(), "mov qword ptr [rip + 0x10], r12");
}

test "lower OI encoding" {
    var enc = TestEncode{};

    try enc.encode(.{ .tag = .mov, .enc = .oi, .data = Instruction.Data.oi(.rax, 0x1000000000000000) });
    try expectEqualHexStrings("\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x10", enc.code(), "movabs rax, 0x1000000000000000");

    try enc.encode(.{ .tag = .mov, .enc = .oi, .data = Instruction.Data.oi(.r11, 0x1000000000000000) });
    try expectEqualHexStrings("\x49\xBB\x00\x00\x00\x00\x00\x00\x00\x10", enc.code(), "movabs r11, 0x1000000000000000");

    try enc.encode(.{ .tag = .mov, .enc = .oi, .data = Instruction.Data.oi(.r11d, 0x10000000) });
    try expectEqualHexStrings("\x41\xBB\x00\x00\x00\x10", enc.code(), "mov r11d, 0x10000000");

    try enc.encode(.{ .tag = .mov, .enc = .oi, .data = Instruction.Data.oi(.r11w, 0x1000) });
    try expectEqualHexStrings("\x66\x41\xBB\x00\x10", enc.code(), "mov r11w, 0x1000");

    try enc.encode(.{ .tag = .mov, .enc = .oi, .data = Instruction.Data.oi(.r11b, 0x10) });
    try expectEqualHexStrings("\x41\xB3\x10", enc.code(), "mov r11b, 0x10");
}
