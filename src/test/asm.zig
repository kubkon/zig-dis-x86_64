const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const bits = @import("../bits.zig");
const encoder = @import("../encoder.zig");
const Assembler = @import("../Assembler.zig");
const Immediate = bits.Immediate;
const Instruction = encoder.Instruction;
const Memory = bits.Memory;
const Mnemonic = Instruction.Mnemonic;
const Operand = Instruction.Operand;
const Register = bits.Register;

fn expectEqualHexStrings(expected: []const u8, given: []const u8, assembly: []const u8) !void {
    assert(expected.len > 0);
    if (std.mem.eql(u8, expected, given)) return;
    const expected_fmt = try std.fmt.allocPrint(testing.allocator, "{x}", .{std.fmt.fmtSliceHexLower(expected)});
    defer testing.allocator.free(expected_fmt);
    const given_fmt = try std.fmt.allocPrint(testing.allocator, "{x}", .{std.fmt.fmtSliceHexLower(given)});
    defer testing.allocator.free(given_fmt);
    const idx = std.mem.indexOfDiff(u8, expected_fmt, given_fmt).?;
    const padding = try testing.allocator.alloc(u8, idx + 5);
    defer testing.allocator.free(padding);
    @memset(padding, ' ');
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

    fn encode(
        enc: *TestEncode,
        mnemonic: Instruction.Mnemonic,
        ops: []const Instruction.Operand,
    ) !void {
        var stream = std.io.fixedBufferStream(&enc.buffer);
        var count_writer = std.io.countingWriter(stream.writer());
        const inst = try Instruction.new(.none, mnemonic, ops);
        try inst.encode(count_writer.writer(), .{});
        enc.index = count_writer.bytes_written;
    }

    fn code(enc: TestEncode) []const u8 {
        return enc.buffer[0..enc.index];
    }
};

test "encode" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    const inst = try Instruction.new(.none, .mov, &.{
        .{ .reg = .rbx },
        .{ .imm = Immediate.u(4) },
    });
    try inst.encode(buf.writer(), .{});
    try testing.expectEqualSlices(u8, &.{ 0x48, 0xc7, 0xc3, 0x4, 0x0, 0x0, 0x0 }, buf.items);
}

test "lower I encoding" {
    var enc = TestEncode{};

    try enc.encode(.push, &.{
        .{ .imm = Immediate.u(0x10) },
    });
    try expectEqualHexStrings("\x6A\x10", enc.code(), "push 0x10");

    try enc.encode(.push, &.{
        .{ .imm = Immediate.u(0x1000) },
    });
    try expectEqualHexStrings("\x66\x68\x00\x10", enc.code(), "push 0x1000");

    try enc.encode(.push, &.{
        .{ .imm = Immediate.u(0x10000000) },
    });
    try expectEqualHexStrings("\x68\x00\x00\x00\x10", enc.code(), "push 0x10000000");

    try enc.encode(.adc, &.{
        .{ .reg = .rax },
        .{ .imm = Immediate.u(0x10000000) },
    });
    try expectEqualHexStrings("\x48\x15\x00\x00\x00\x10", enc.code(), "adc rax, 0x10000000");

    try enc.encode(.add, &.{
        .{ .reg = .al },
        .{ .imm = Immediate.u(0x10) },
    });
    try expectEqualHexStrings("\x04\x10", enc.code(), "add al, 0x10");

    try enc.encode(.add, &.{
        .{ .reg = .rax },
        .{ .imm = Immediate.u(0x10) },
    });
    try expectEqualHexStrings("\x48\x83\xC0\x10", enc.code(), "add rax, 0x10");

    try enc.encode(.sbb, &.{
        .{ .reg = .ax },
        .{ .imm = Immediate.u(0x10) },
    });
    try expectEqualHexStrings("\x66\x1D\x10\x00", enc.code(), "sbb ax, 0x10");

    try enc.encode(.xor, &.{
        .{ .reg = .al },
        .{ .imm = Immediate.u(0x10) },
    });
    try expectEqualHexStrings("\x34\x10", enc.code(), "xor al, 0x10");
}

test "lower MI encoding" {
    var enc = TestEncode{};

    try enc.encode(.mov, &.{
        .{ .reg = .r12 },
        .{ .imm = Immediate.u(0x1000) },
    });
    try expectEqualHexStrings("\x49\xC7\xC4\x00\x10\x00\x00", enc.code(), "mov r12, 0x1000");

    try enc.encode(.mov, &.{
        .{ .mem = Memory.sib(.byte, .{ .base = .{ .reg = .r12 } }) },
        .{ .imm = Immediate.u(0x10) },
    });
    try expectEqualHexStrings("\x41\xC6\x04\x24\x10", enc.code(), "mov BYTE PTR [r12], 0x10");

    try enc.encode(.mov, &.{
        .{ .reg = .r12 },
        .{ .imm = Immediate.u(0x1000) },
    });
    try expectEqualHexStrings("\x49\xC7\xC4\x00\x10\x00\x00", enc.code(), "mov r12, 0x1000");

    try enc.encode(.mov, &.{
        .{ .reg = .r12 },
        .{ .imm = Immediate.u(0x1000) },
    });
    try expectEqualHexStrings("\x49\xC7\xC4\x00\x10\x00\x00", enc.code(), "mov r12, 0x1000");

    try enc.encode(.mov, &.{
        .{ .reg = .rax },
        .{ .imm = Immediate.u(0x10) },
    });
    try expectEqualHexStrings("\x48\xc7\xc0\x10\x00\x00\x00", enc.code(), "mov rax, 0x10");

    try enc.encode(.mov, &.{
        .{ .mem = Memory.sib(.dword, .{ .base = .{ .reg = .r11 } }) },
        .{ .imm = Immediate.u(0x10) },
    });
    try expectEqualHexStrings("\x41\xc7\x03\x10\x00\x00\x00", enc.code(), "mov DWORD PTR [r11], 0x10");

    try enc.encode(.mov, &.{
        .{ .mem = Memory.rip(.qword, 0x10) },
        .{ .imm = Immediate.u(0x10) },
    });
    try expectEqualHexStrings(
        "\x48\xC7\x05\x10\x00\x00\x00\x10\x00\x00\x00",
        enc.code(),
        "mov QWORD PTR [rip + 0x10], 0x10",
    );

    try enc.encode(.mov, &.{
        .{ .mem = Memory.sib(.qword, .{ .base = .{ .reg = .rbp }, .disp = -8 }) },
        .{ .imm = Immediate.u(0x10) },
    });
    try expectEqualHexStrings("\x48\xc7\x45\xf8\x10\x00\x00\x00", enc.code(), "mov QWORD PTR [rbp - 8], 0x10");

    try enc.encode(.mov, &.{
        .{ .mem = Memory.sib(.word, .{ .base = .{ .reg = .rbp }, .disp = -2 }) },
        .{ .imm = Immediate.s(-16) },
    });
    try expectEqualHexStrings("\x66\xC7\x45\xFE\xF0\xFF", enc.code(), "mov WORD PTR [rbp - 2], -16");

    try enc.encode(.mov, &.{
        .{ .mem = Memory.sib(.byte, .{ .base = .{ .reg = .rbp }, .disp = -1 }) },
        .{ .imm = Immediate.u(0x10) },
    });
    try expectEqualHexStrings("\xC6\x45\xFF\x10", enc.code(), "mov BYTE PTR [rbp - 1], 0x10");

    try enc.encode(.mov, &.{
        .{ .mem = Memory.sib(.qword, .{
            .base = .{ .reg = .ds },
            .disp = 0x10000000,
            .scale_index = .{ .scale = 2, .index = .rcx },
        }) },
        .{ .imm = Immediate.u(0x10) },
    });
    try expectEqualHexStrings(
        "\x48\xC7\x04\x4D\x00\x00\x00\x10\x10\x00\x00\x00",
        enc.code(),
        "mov QWORD PTR [rcx*2 + 0x10000000], 0x10",
    );

    try enc.encode(.adc, &.{
        .{ .mem = Memory.sib(.byte, .{ .base = .{ .reg = .rbp }, .disp = -0x10 }) },
        .{ .imm = Immediate.u(0x10) },
    });
    try expectEqualHexStrings("\x80\x55\xF0\x10", enc.code(), "adc BYTE PTR [rbp - 0x10], 0x10");

    try enc.encode(.adc, &.{
        .{ .mem = Memory.rip(.qword, 0) },
        .{ .imm = Immediate.u(0x10) },
    });
    try expectEqualHexStrings("\x48\x83\x15\x00\x00\x00\x00\x10", enc.code(), "adc QWORD PTR [rip], 0x10");

    try enc.encode(.adc, &.{
        .{ .reg = .rax },
        .{ .imm = Immediate.u(0x10) },
    });
    try expectEqualHexStrings("\x48\x83\xD0\x10", enc.code(), "adc rax, 0x10");

    try enc.encode(.add, &.{
        .{ .mem = Memory.sib(.dword, .{ .base = .{ .reg = .rdx }, .disp = -8 }) },
        .{ .imm = Immediate.u(0x10) },
    });
    try expectEqualHexStrings("\x83\x42\xF8\x10", enc.code(), "add DWORD PTR [rdx - 8], 0x10");

    try enc.encode(.add, &.{
        .{ .reg = .rax },
        .{ .imm = Immediate.u(0x10) },
    });
    try expectEqualHexStrings("\x48\x83\xC0\x10", enc.code(), "add rax, 0x10");

    try enc.encode(.add, &.{
        .{ .mem = Memory.sib(.qword, .{ .base = .{ .reg = .rbp }, .disp = -0x10 }) },
        .{ .imm = Immediate.s(-0x10) },
    });
    try expectEqualHexStrings("\x48\x83\x45\xF0\xF0", enc.code(), "add QWORD PTR [rbp - 0x10], -0x10");

    try enc.encode(.@"and", &.{
        .{ .mem = Memory.sib(.dword, .{ .base = .{ .reg = .ds }, .disp = 0x10000000 }) },
        .{ .imm = Immediate.u(0x10) },
    });
    try expectEqualHexStrings(
        "\x83\x24\x25\x00\x00\x00\x10\x10",
        enc.code(),
        "and DWORD PTR ds:0x10000000, 0x10",
    );

    try enc.encode(.@"and", &.{
        .{ .mem = Memory.sib(.dword, .{ .base = .{ .reg = .es }, .disp = 0x10000000 }) },
        .{ .imm = Immediate.u(0x10) },
    });
    try expectEqualHexStrings(
        "\x26\x83\x24\x25\x00\x00\x00\x10\x10",
        enc.code(),
        "and DWORD PTR es:0x10000000, 0x10",
    );

    try enc.encode(.@"and", &.{
        .{ .mem = Memory.sib(.dword, .{ .base = .{ .reg = .r12 }, .disp = 0x10000000 }) },
        .{ .imm = Immediate.u(0x10) },
    });
    try expectEqualHexStrings(
        "\x41\x83\xA4\x24\x00\x00\x00\x10\x10",
        enc.code(),
        "and DWORD PTR [r12 + 0x10000000], 0x10",
    );

    try enc.encode(.sub, &.{
        .{ .mem = Memory.sib(.dword, .{ .base = .{ .reg = .r11 }, .disp = 0x10000000 }) },
        .{ .imm = Immediate.u(0x10) },
    });
    try expectEqualHexStrings(
        "\x41\x83\xAB\x00\x00\x00\x10\x10",
        enc.code(),
        "sub DWORD PTR [r11 + 0x10000000], 0x10",
    );
}

test "lower RM encoding" {
    var enc = TestEncode{};

    try enc.encode(.mov, &.{
        .{ .reg = .rax },
        .{ .mem = Memory.sib(.qword, .{ .base = .{ .reg = .r11 } }) },
    });
    try expectEqualHexStrings("\x49\x8b\x03", enc.code(), "mov rax, QWORD PTR [r11]");

    try enc.encode(.mov, &.{
        .{ .reg = .rbx },
        .{ .mem = Memory.sib(.qword, .{ .base = .{ .reg = .ds }, .disp = 0x10 }) },
    });
    try expectEqualHexStrings("\x48\x8B\x1C\x25\x10\x00\x00\x00", enc.code(), "mov rbx, QWORD PTR ds:0x10");

    try enc.encode(.mov, &.{
        .{ .reg = .rax },
        .{ .mem = Memory.sib(.qword, .{ .base = .{ .reg = .rbp }, .disp = -4 }) },
    });
    try expectEqualHexStrings("\x48\x8B\x45\xFC", enc.code(), "mov rax, QWORD PTR [rbp - 4]");

    try enc.encode(.mov, &.{
        .{ .reg = .rax },
        .{ .mem = Memory.sib(.qword, .{
            .base = .{ .reg = .rbp },
            .scale_index = .{ .scale = 1, .index = .rcx },
            .disp = -8,
        }) },
    });
    try expectEqualHexStrings("\x48\x8B\x44\x0D\xF8", enc.code(), "mov rax, QWORD PTR [rbp + rcx*1 - 8]");

    try enc.encode(.mov, &.{
        .{ .reg = .eax },
        .{ .mem = Memory.sib(.dword, .{
            .base = .{ .reg = .rbp },
            .scale_index = .{ .scale = 4, .index = .rdx },
            .disp = -4,
        }) },
    });
    try expectEqualHexStrings("\x8B\x44\x95\xFC", enc.code(), "mov eax, dword ptr [rbp + rdx*4 - 4]");

    try enc.encode(.mov, &.{
        .{ .reg = .rax },
        .{ .mem = Memory.sib(.qword, .{
            .base = .{ .reg = .rbp },
            .scale_index = .{ .scale = 8, .index = .rcx },
            .disp = -8,
        }) },
    });
    try expectEqualHexStrings("\x48\x8B\x44\xCD\xF8", enc.code(), "mov rax, QWORD PTR [rbp + rcx*8 - 8]");

    try enc.encode(.mov, &.{
        .{ .reg = .r8b },
        .{ .mem = Memory.sib(.byte, .{
            .base = .{ .reg = .rsi },
            .scale_index = .{ .scale = 1, .index = .rcx },
            .disp = -24,
        }) },
    });
    try expectEqualHexStrings("\x44\x8A\x44\x0E\xE8", enc.code(), "mov r8b, BYTE PTR [rsi + rcx*1 - 24]");

    // TODO this mnemonic needs cleanup as some prefixes are obsolete.
    try enc.encode(.mov, &.{
        .{ .reg = .rax },
        .{ .reg = .cs },
    });
    try expectEqualHexStrings("\x48\x8C\xC8", enc.code(), "mov rax, cs");

    try enc.encode(.mov, &.{
        .{ .reg = .r12w },
        .{ .reg = .cs },
    });
    try expectEqualHexStrings("\x66\x41\x8C\xCC", enc.code(), "mov r12w, cs");

    try enc.encode(.mov, &.{
        .{ .mem = Memory.sib(.word, .{ .base = .{ .reg = .rbp }, .disp = -16 }) },
        .{ .reg = .fs },
    });
    try expectEqualHexStrings("\x8C\x65\xF0", enc.code(), "mov WORD PTR [rbp - 16], fs");

    try enc.encode(.movsx, &.{
        .{ .reg = .eax },
        .{ .reg = .bx },
    });
    try expectEqualHexStrings("\x0F\xBF\xC3", enc.code(), "movsx eax, bx");

    try enc.encode(.movsx, &.{
        .{ .reg = .eax },
        .{ .reg = .bl },
    });
    try expectEqualHexStrings("\x0F\xBE\xC3", enc.code(), "movsx eax, bl");

    try enc.encode(.movsx, &.{
        .{ .reg = .ax },
        .{ .reg = .bl },
    });
    try expectEqualHexStrings("\x66\x0F\xBE\xC3", enc.code(), "movsx ax, bl");

    try enc.encode(.movsx, &.{
        .{ .reg = .eax },
        .{ .mem = Memory.sib(.word, .{ .base = .{ .reg = .rbp } }) },
    });
    try expectEqualHexStrings("\x0F\xBF\x45\x00", enc.code(), "movsx eax, BYTE PTR [rbp]");

    try enc.encode(.movsx, &.{
        .{ .reg = .eax },
        .{ .mem = Memory.sib(.byte, .{ .scale_index = .{ .index = .rax, .scale = 2 } }) },
    });
    try expectEqualHexStrings("\x0F\xBE\x04\x45\x00\x00\x00\x00", enc.code(), "movsx eax, BYTE PTR [rax * 2]");

    try enc.encode(.movsx, &.{
        .{ .reg = .ax },
        .{ .mem = Memory.rip(.byte, 0x10) },
    });
    try expectEqualHexStrings("\x66\x0F\xBE\x05\x10\x00\x00\x00", enc.code(), "movsx ax, BYTE PTR [rip + 0x10]");

    try enc.encode(.movsx, &.{
        .{ .reg = .rax },
        .{ .reg = .bx },
    });
    try expectEqualHexStrings("\x48\x0F\xBF\xC3", enc.code(), "movsx rax, bx");

    try enc.encode(.movsxd, &.{
        .{ .reg = .rax },
        .{ .reg = .ebx },
    });
    try expectEqualHexStrings("\x48\x63\xC3", enc.code(), "movsxd rax, ebx");

    try enc.encode(.lea, &.{
        .{ .reg = .rax },
        .{ .mem = Memory.rip(.qword, 0x10) },
    });
    try expectEqualHexStrings("\x48\x8D\x05\x10\x00\x00\x00", enc.code(), "lea rax, QWORD PTR [rip + 0x10]");

    try enc.encode(.lea, &.{
        .{ .reg = .rax },
        .{ .mem = Memory.rip(.dword, 0x10) },
    });
    try expectEqualHexStrings("\x48\x8D\x05\x10\x00\x00\x00", enc.code(), "lea rax, DWORD PTR [rip + 0x10]");

    try enc.encode(.lea, &.{
        .{ .reg = .eax },
        .{ .mem = Memory.rip(.dword, 0x10) },
    });
    try expectEqualHexStrings("\x8D\x05\x10\x00\x00\x00", enc.code(), "lea eax, DWORD PTR [rip + 0x10]");

    try enc.encode(.lea, &.{
        .{ .reg = .eax },
        .{ .mem = Memory.rip(.word, 0x10) },
    });
    try expectEqualHexStrings("\x8D\x05\x10\x00\x00\x00", enc.code(), "lea eax, WORD PTR [rip + 0x10]");

    try enc.encode(.lea, &.{
        .{ .reg = .ax },
        .{ .mem = Memory.rip(.byte, 0x10) },
    });
    try expectEqualHexStrings("\x66\x8D\x05\x10\x00\x00\x00", enc.code(), "lea ax, BYTE PTR [rip + 0x10]");

    try enc.encode(.lea, &.{
        .{ .reg = .rsi },
        .{ .mem = Memory.sib(.qword, .{
            .base = .{ .reg = .rbp },
            .scale_index = .{ .scale = 1, .index = .rcx },
        }) },
    });
    try expectEqualHexStrings("\x48\x8D\x74\x0D\x00", enc.code(), "lea rsi, QWORD PTR [rbp + rcx*1 + 0]");

    try enc.encode(.add, &.{
        .{ .reg = .r11 },
        .{ .mem = Memory.sib(.qword, .{ .base = .{ .reg = .ds }, .disp = 0x10000000 }) },
    });
    try expectEqualHexStrings("\x4C\x03\x1C\x25\x00\x00\x00\x10", enc.code(), "add r11, QWORD PTR ds:0x10000000");

    try enc.encode(.add, &.{
        .{ .reg = .r12b },
        .{ .mem = Memory.sib(.byte, .{ .base = .{ .reg = .ds }, .disp = 0x10000000 }) },
    });
    try expectEqualHexStrings("\x44\x02\x24\x25\x00\x00\x00\x10", enc.code(), "add r11b, BYTE PTR ds:0x10000000");

    try enc.encode(.add, &.{
        .{ .reg = .r12b },
        .{ .mem = Memory.sib(.byte, .{ .base = .{ .reg = .fs }, .disp = 0x10000000 }) },
    });
    try expectEqualHexStrings("\x64\x44\x02\x24\x25\x00\x00\x00\x10", enc.code(), "add r11b, BYTE PTR fs:0x10000000");

    try enc.encode(.sub, &.{
        .{ .reg = .r11 },
        .{ .mem = Memory.sib(.qword, .{ .base = .{ .reg = .r13 }, .disp = 0x10000000 }) },
    });
    try expectEqualHexStrings("\x4D\x2B\x9D\x00\x00\x00\x10", enc.code(), "sub r11, QWORD PTR [r13 + 0x10000000]");

    try enc.encode(.sub, &.{
        .{ .reg = .r11 },
        .{ .mem = Memory.sib(.qword, .{ .base = .{ .reg = .r12 }, .disp = 0x10000000 }) },
    });
    try expectEqualHexStrings("\x4D\x2B\x9C\x24\x00\x00\x00\x10", enc.code(), "sub r11, QWORD PTR [r12 + 0x10000000]");

    try enc.encode(.imul, &.{
        .{ .reg = .r11 },
        .{ .reg = .r12 },
    });
    try expectEqualHexStrings("\x4D\x0F\xAF\xDC", enc.code(), "mov r11, r12");
}

test "lower RMI encoding" {
    var enc = TestEncode{};

    try enc.encode(.imul, &.{
        .{ .reg = .r11 },
        .{ .reg = .r12 },
        .{ .imm = Immediate.s(-2) },
    });
    try expectEqualHexStrings("\x4D\x6B\xDC\xFE", enc.code(), "imul r11, r12, -2");

    try enc.encode(.imul, &.{
        .{ .reg = .r11 },
        .{ .mem = Memory.rip(.qword, -16) },
        .{ .imm = Immediate.s(-1024) },
    });
    try expectEqualHexStrings(
        "\x4C\x69\x1D\xF0\xFF\xFF\xFF\x00\xFC\xFF\xFF",
        enc.code(),
        "imul r11, QWORD PTR [rip - 16], -1024",
    );

    try enc.encode(.imul, &.{
        .{ .reg = .bx },
        .{ .mem = Memory.sib(.word, .{ .base = .{ .reg = .rbp }, .disp = -16 }) },
        .{ .imm = Immediate.s(-1024) },
    });
    try expectEqualHexStrings(
        "\x66\x69\x5D\xF0\x00\xFC",
        enc.code(),
        "imul bx, WORD PTR [rbp - 16], -1024",
    );

    try enc.encode(.imul, &.{
        .{ .reg = .bx },
        .{ .mem = Memory.sib(.word, .{ .base = .{ .reg = .rbp }, .disp = -16 }) },
        .{ .imm = Immediate.u(1024) },
    });
    try expectEqualHexStrings(
        "\x66\x69\x5D\xF0\x00\x04",
        enc.code(),
        "imul bx, WORD PTR [rbp - 16], 1024",
    );
}

test "lower MR encoding" {
    var enc = TestEncode{};

    try enc.encode(.mov, &.{
        .{ .reg = .rax },
        .{ .reg = .rbx },
    });
    try expectEqualHexStrings("\x48\x89\xD8", enc.code(), "mov rax, rbx");

    try enc.encode(.mov, &.{
        .{ .mem = Memory.sib(.qword, .{ .base = .{ .reg = .rbp }, .disp = -4 }) },
        .{ .reg = .r11 },
    });
    try expectEqualHexStrings("\x4c\x89\x5d\xfc", enc.code(), "mov QWORD PTR [rbp - 4], r11");

    try enc.encode(.mov, &.{
        .{ .mem = Memory.rip(.qword, 0x10) },
        .{ .reg = .r12 },
    });
    try expectEqualHexStrings("\x4C\x89\x25\x10\x00\x00\x00", enc.code(), "mov QWORD PTR [rip + 0x10], r12");

    try enc.encode(.mov, &.{
        .{ .mem = Memory.sib(.qword, .{
            .base = .{ .reg = .r11 },
            .scale_index = .{ .scale = 2, .index = .r12 },
            .disp = 0x10,
        }) },
        .{ .reg = .r13 },
    });
    try expectEqualHexStrings("\x4F\x89\x6C\x63\x10", enc.code(), "mov QWORD PTR [r11 + 2 * r12 + 0x10], r13");

    try enc.encode(.mov, &.{
        .{ .mem = Memory.rip(.word, -0x10) },
        .{ .reg = .r12w },
    });
    try expectEqualHexStrings("\x66\x44\x89\x25\xF0\xFF\xFF\xFF", enc.code(), "mov WORD PTR [rip - 0x10], r12w");

    try enc.encode(.mov, &.{
        .{ .mem = Memory.sib(.byte, .{
            .base = .{ .reg = .r11 },
            .scale_index = .{ .scale = 2, .index = .r12 },
            .disp = 0x10,
        }) },
        .{ .reg = .r13b },
    });
    try expectEqualHexStrings("\x47\x88\x6C\x63\x10", enc.code(), "mov BYTE PTR [r11 + 2 * r12 + 0x10], r13b");

    try enc.encode(.add, &.{
        .{ .mem = Memory.sib(.byte, .{ .base = .{ .reg = .ds }, .disp = 0x10000000 }) },
        .{ .reg = .r12b },
    });
    try expectEqualHexStrings("\x44\x00\x24\x25\x00\x00\x00\x10", enc.code(), "add BYTE PTR ds:0x10000000, r12b");

    try enc.encode(.add, &.{
        .{ .mem = Memory.sib(.dword, .{ .base = .{ .reg = .ds }, .disp = 0x10000000 }) },
        .{ .reg = .r12d },
    });
    try expectEqualHexStrings("\x44\x01\x24\x25\x00\x00\x00\x10", enc.code(), "add DWORD PTR [ds:0x10000000], r12d");

    try enc.encode(.add, &.{
        .{ .mem = Memory.sib(.dword, .{ .base = .{ .reg = .gs }, .disp = 0x10000000 }) },
        .{ .reg = .r12d },
    });
    try expectEqualHexStrings("\x65\x44\x01\x24\x25\x00\x00\x00\x10", enc.code(), "add DWORD PTR [gs:0x10000000], r12d");

    try enc.encode(.sub, &.{
        .{ .mem = Memory.sib(.qword, .{ .base = .{ .reg = .r11 }, .disp = 0x10000000 }) },
        .{ .reg = .r12 },
    });
    try expectEqualHexStrings("\x4D\x29\xA3\x00\x00\x00\x10", enc.code(), "sub QWORD PTR [r11 + 0x10000000], r12");
}

test "lower M encoding" {
    var enc = TestEncode{};

    try enc.encode(.call, &.{
        .{ .reg = .r12 },
    });
    try expectEqualHexStrings("\x41\xFF\xD4", enc.code(), "call r12");

    try enc.encode(.call, &.{
        .{ .mem = Memory.sib(.qword, .{ .base = .{ .reg = .r12 } }) },
    });
    try expectEqualHexStrings("\x41\xFF\x14\x24", enc.code(), "call QWORD PTR [r12]");

    try enc.encode(.call, &.{
        .{ .mem = Memory.sib(.qword, .{
            .base = .none,
            .scale_index = .{ .index = .r11, .scale = 2 },
        }) },
    });
    try expectEqualHexStrings("\x42\xFF\x14\x5D\x00\x00\x00\x00", enc.code(), "call QWORD PTR [r11 * 2]");

    try enc.encode(.call, &.{
        .{ .mem = Memory.sib(.qword, .{
            .base = .none,
            .scale_index = .{ .index = .r12, .scale = 2 },
        }) },
    });
    try expectEqualHexStrings("\x42\xFF\x14\x65\x00\x00\x00\x00", enc.code(), "call QWORD PTR [r12 * 2]");

    try enc.encode(.call, &.{
        .{ .mem = Memory.sib(.qword, .{ .base = .{ .reg = .gs } }) },
    });
    try expectEqualHexStrings("\x65\xFF\x14\x25\x00\x00\x00\x00", enc.code(), "call gs:0x0");

    try enc.encode(.call, &.{
        .{ .imm = Immediate.s(0) },
    });
    try expectEqualHexStrings("\xE8\x00\x00\x00\x00", enc.code(), "call 0x0");

    try enc.encode(.push, &.{
        .{ .mem = Memory.sib(.qword, .{ .base = .{ .reg = .rbp } }) },
    });
    try expectEqualHexStrings("\xFF\x75\x00", enc.code(), "push QWORD PTR [rbp]");

    try enc.encode(.push, &.{
        .{ .mem = Memory.sib(.word, .{ .base = .{ .reg = .rbp } }) },
    });
    try expectEqualHexStrings("\x66\xFF\x75\x00", enc.code(), "push QWORD PTR [rbp]");

    try enc.encode(.pop, &.{
        .{ .mem = Memory.rip(.qword, 0) },
    });
    try expectEqualHexStrings("\x8F\x05\x00\x00\x00\x00", enc.code(), "pop QWORD PTR [rip]");

    try enc.encode(.pop, &.{
        .{ .mem = Memory.rip(.word, 0) },
    });
    try expectEqualHexStrings("\x66\x8F\x05\x00\x00\x00\x00", enc.code(), "pop WORD PTR [rbp]");

    try enc.encode(.imul, &.{
        .{ .reg = .rax },
    });
    try expectEqualHexStrings("\x48\xF7\xE8", enc.code(), "imul rax");

    try enc.encode(.imul, &.{
        .{ .reg = .r12 },
    });
    try expectEqualHexStrings("\x49\xF7\xEC", enc.code(), "imul r12");
}

test "lower O encoding" {
    var enc = TestEncode{};

    try enc.encode(.push, &.{
        .{ .reg = .rax },
    });
    try expectEqualHexStrings("\x50", enc.code(), "push rax");

    try enc.encode(.push, &.{
        .{ .reg = .r12w },
    });
    try expectEqualHexStrings("\x66\x41\x54", enc.code(), "push r12w");

    try enc.encode(.pop, &.{
        .{ .reg = .r12 },
    });
    try expectEqualHexStrings("\x41\x5c", enc.code(), "pop r12");
}

test "lower OI encoding" {
    var enc = TestEncode{};

    try enc.encode(.mov, &.{
        .{ .reg = .rax },
        .{ .imm = Immediate.u(0x1000000000000000) },
    });
    try expectEqualHexStrings(
        "\x48\xB8\x00\x00\x00\x00\x00\x00\x00\x10",
        enc.code(),
        "movabs rax, 0x1000000000000000",
    );

    try enc.encode(.mov, &.{
        .{ .reg = .r11 },
        .{ .imm = Immediate.u(0x1000000000000000) },
    });
    try expectEqualHexStrings(
        "\x49\xBB\x00\x00\x00\x00\x00\x00\x00\x10",
        enc.code(),
        "movabs r11, 0x1000000000000000",
    );

    try enc.encode(.mov, &.{
        .{ .reg = .r11d },
        .{ .imm = Immediate.u(0x10000000) },
    });
    try expectEqualHexStrings("\x41\xBB\x00\x00\x00\x10", enc.code(), "mov r11d, 0x10000000");

    try enc.encode(.mov, &.{
        .{ .reg = .r11w },
        .{ .imm = Immediate.u(0x1000) },
    });
    try expectEqualHexStrings("\x66\x41\xBB\x00\x10", enc.code(), "mov r11w, 0x1000");

    try enc.encode(.mov, &.{
        .{ .reg = .r11b },
        .{ .imm = Immediate.u(0x10) },
    });
    try expectEqualHexStrings("\x41\xB3\x10", enc.code(), "mov r11b, 0x10");
}

test "lower FD/TD encoding" {
    var enc = TestEncode{};

    try enc.encode(.mov, &.{
        .{ .reg = .rax },
        .{ .mem = Memory.moffs(.cs, 0x10) },
    });
    try expectEqualHexStrings("\x2E\x48\xA1\x10\x00\x00\x00\x00\x00\x00\x00", enc.code(), "movabs rax, cs:0x10");

    try enc.encode(.mov, &.{
        .{ .reg = .eax },
        .{ .mem = Memory.moffs(.fs, 0x10) },
    });
    try expectEqualHexStrings("\x64\xA1\x10\x00\x00\x00\x00\x00\x00\x00", enc.code(), "movabs eax, fs:0x10");

    try enc.encode(.mov, &.{
        .{ .reg = .ax },
        .{ .mem = Memory.moffs(.gs, 0x10) },
    });
    try expectEqualHexStrings("\x65\x66\xA1\x10\x00\x00\x00\x00\x00\x00\x00", enc.code(), "movabs ax, gs:0x10");

    try enc.encode(.mov, &.{
        .{ .reg = .al },
        .{ .mem = Memory.moffs(.ds, 0x10) },
    });
    try expectEqualHexStrings("\xA0\x10\x00\x00\x00\x00\x00\x00\x00", enc.code(), "movabs al, ds:0x10");

    try enc.encode(.mov, &.{
        .{ .mem = Memory.moffs(.cs, 0x10) },
        .{ .reg = .rax },
    });
    try expectEqualHexStrings("\x2E\x48\xA3\x10\x00\x00\x00\x00\x00\x00\x00", enc.code(), "movabs cs:0x10, rax");

    try enc.encode(.mov, &.{
        .{ .mem = Memory.moffs(.fs, 0x10) },
        .{ .reg = .eax },
    });
    try expectEqualHexStrings("\x64\xA3\x10\x00\x00\x00\x00\x00\x00\x00", enc.code(), "movabs fs:0x10, eax");

    try enc.encode(.mov, &.{
        .{ .mem = Memory.moffs(.gs, 0x10) },
        .{ .reg = .ax },
    });
    try expectEqualHexStrings("\x65\x66\xA3\x10\x00\x00\x00\x00\x00\x00\x00", enc.code(), "movabs gs:0x10, ax");

    try enc.encode(.mov, &.{
        .{ .mem = Memory.moffs(.ds, 0x10) },
        .{ .reg = .al },
    });
    try expectEqualHexStrings("\xA2\x10\x00\x00\x00\x00\x00\x00\x00", enc.code(), "movabs ds:0x10, al");
}

test "lower NP encoding" {
    var enc = TestEncode{};

    try enc.encode(.int3, &.{});
    try expectEqualHexStrings("\xCC", enc.code(), "int3");

    try enc.encode(.nop, &.{});
    try expectEqualHexStrings("\x90", enc.code(), "nop");

    try enc.encode(.ret, &.{});
    try expectEqualHexStrings("\xC3", enc.code(), "ret");

    try enc.encode(.syscall, &.{});
    try expectEqualHexStrings("\x0f\x05", enc.code(), "syscall");
}

fn invalidInstruction(mnemonic: Instruction.Mnemonic, ops: []const Instruction.Operand) !void {
    const err = Instruction.new(.none, mnemonic, ops);
    try testing.expectError(error.InvalidInstruction, err);
}

test "invalid instruction" {
    try invalidInstruction(.call, &.{
        .{ .reg = .eax },
    });
    try invalidInstruction(.call, &.{
        .{ .reg = .ax },
    });
    try invalidInstruction(.call, &.{
        .{ .reg = .al },
    });
    try invalidInstruction(.call, &.{
        .{ .mem = Memory.rip(.dword, 0) },
    });
    try invalidInstruction(.call, &.{
        .{ .mem = Memory.rip(.word, 0) },
    });
    try invalidInstruction(.call, &.{
        .{ .mem = Memory.rip(.byte, 0) },
    });
    try invalidInstruction(.mov, &.{
        .{ .mem = Memory.rip(.word, 0x10) },
        .{ .reg = .r12 },
    });
    try invalidInstruction(.lea, &.{
        .{ .reg = .rax },
        .{ .reg = .rbx },
    });
    try invalidInstruction(.lea, &.{
        .{ .reg = .al },
        .{ .mem = Memory.rip(.byte, 0) },
    });
    try invalidInstruction(.pop, &.{
        .{ .reg = .r12b },
    });
    try invalidInstruction(.pop, &.{
        .{ .reg = .r12d },
    });
    try invalidInstruction(.push, &.{
        .{ .reg = .r12b },
    });
    try invalidInstruction(.push, &.{
        .{ .reg = .r12d },
    });
    try invalidInstruction(.push, &.{
        .{ .imm = Immediate.u(0x1000000000000000) },
    });
}

fn cannotEncode(mnemonic: Instruction.Mnemonic, ops: []const Instruction.Operand) !void {
    try testing.expectError(error.CannotEncode, Instruction.new(.none, mnemonic, ops));
}

test "cannot encode" {
    try cannotEncode(.@"test", &.{
        .{ .mem = Memory.sib(.byte, .{ .base = .{ .reg = .r12 } }) },
        .{ .reg = .ah },
    });
    try cannotEncode(.@"test", &.{
        .{ .reg = .r11b },
        .{ .reg = .bh },
    });
    try cannotEncode(.mov, &.{
        .{ .reg = .sil },
        .{ .reg = .ah },
    });
}

test "assemble" {
    const input =
        \\int3
        \\mov rax, rbx
        \\mov qword ptr [rbp], rax
        \\mov qword ptr [rbp - 16], rax
        \\mov qword ptr [16 + rbp], rax
        \\mov rax, 0x10
        \\mov byte ptr [rbp - 0x10], 0x10
        \\mov word ptr [rbp + r12], r11w
        \\mov word ptr [rbp + r12 * 2], r11w
        \\mov word ptr [rbp + r12 * 2 - 16], r11w
        \\mov dword ptr [rip - 16], r12d
        \\mov rax, fs:0x0
        \\mov rax, gs:0x1000000000000000
        \\movzx r12, al
        \\imul r12, qword ptr [rbp - 16], 6
        \\jmp 0x0
        \\jc 0x0
        \\jb 0x0
        \\sal rax, 1
        \\sal rax, 63
        \\shl rax, 63
        \\sar rax, 63
        \\shr rax, 63
        \\test byte ptr [rbp - 16], r12b
        \\sal r12, cl
        \\mul qword ptr [rip - 16]
        \\div r12
        \\idiv byte ptr [rbp - 16]
        \\cwde
        \\cbw
        \\cdqe
        \\test byte ptr [rbp], ah
        \\test byte ptr [r12], spl
        \\cdq
        \\cwd
        \\cqo
        \\test bl, 0x1
        \\mov rbx,0x8000000000000000
        \\movss xmm0, dword ptr [rbp]
        \\movss xmm0, xmm1
        \\movss dword ptr [rbp - 16 + rax * 2], xmm7
        \\movss dword ptr [rbp - 16 + rax * 2], xmm8
        \\movss xmm15, xmm9
        \\movsd xmm8, qword ptr [rbp - 16]
        \\movsd qword ptr [rbp - 8], xmm0
        \\ucomisd xmm0, qword ptr [rbp - 16]
        \\fisttp qword ptr [rbp - 16]
        \\fisttp word ptr [rip + 32]
        \\fisttp dword ptr [rax]
        \\fld tbyte ptr [rbp]
        \\fld dword ptr [rbp]
        \\xor bl, 0xff
        \\ud2
        \\add rsp, -1
        \\add rsp, 0xff
        \\mov sil, byte ptr [rax + rcx * 1]
        \\leave
        \\endbr64
        \\
    ;

    // zig fmt: off
    const expected = &[_]u8{
        0xCC,
        0x48, 0x89, 0xD8,
        0x48, 0x89, 0x45, 0x00,
        0x48, 0x89, 0x45, 0xF0,
        0x48, 0x89, 0x45, 0x10,
        0x48, 0xC7, 0xC0, 0x10, 0x00, 0x00, 0x00,
        0xC6, 0x45, 0xF0, 0x10,
        0x66, 0x46, 0x89, 0x5C, 0x25, 0x00,
        0x66, 0x46, 0x89, 0x5C, 0x65, 0x00,
        0x66, 0x46, 0x89, 0x5C, 0x65, 0xF0,
        0x44, 0x89, 0x25, 0xF0, 0xFF, 0xFF, 0xFF,
        0x64, 0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x65, 0x48, 0xA1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        0x4C, 0x0F, 0xB6, 0xE0,
        0x4C, 0x6B, 0x65, 0xF0, 0x06,
        0xE9, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x82, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x82, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xD1, 0xE0,
        0x48, 0xC1, 0xE0, 0x3F,
        0x48, 0xC1, 0xE0, 0x3F,
        0x48, 0xC1, 0xF8, 0x3F,
        0x48, 0xC1, 0xE8, 0x3F,
        0x44, 0x84, 0x65, 0xF0,
        0x49, 0xD3, 0xE4,
        0x48, 0xF7, 0x25, 0xF0, 0xFF, 0xFF, 0xFF,
        0x49, 0xF7, 0xF4,
        0xF6, 0x7D, 0xF0,
        0x98,
        0x66, 0x98,
        0x48, 0x98,
        0x84, 0x65, 0x00,
        0x41, 0x84, 0x24, 0x24,
        0x99,
        0x66, 0x99,
        0x48, 0x99,
        0xF6, 0xC3, 0x01,
        0x48, 0xBB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80,
        0xF3, 0x0F, 0x10, 0x45, 0x00,
        0xF3, 0x0F, 0x10, 0xC1,
        0xF3, 0x0F, 0x11, 0x7C, 0x45, 0xF0,
        0xF3, 0x44, 0x0F, 0x11, 0x44, 0x45, 0xF0,
        0xF3, 0x45, 0x0F, 0x10, 0xF9,
        0xF2, 0x44, 0x0F, 0x10, 0x45, 0xF0,
        0xF2, 0x0F, 0x11, 0x45, 0xF8,
        0x66, 0x0F, 0x2E, 0x45, 0xF0,
        0xDD, 0x4D, 0xF0,
        0xDF, 0x0D, 0x20, 0x00, 0x00, 0x00,
        0xDB, 0x08,
        0xDB, 0x6D, 0x00,
        0xD9, 0x45, 0x00,
        0x80, 0xF3, 0xFF,
        0x0F, 0x0B,
        0x48, 0x83, 0xC4, 0xFF,
        0x48, 0x81, 0xC4, 0xFF, 0x00, 0x00, 0x00,
        0x40, 0x8A, 0x34, 0x08,
        0xC9,
        0xF3, 0x0F, 0x1E, 0xFA,
    };
    // zig fmt: on

    var as = Assembler.init(input);
    var output = std.ArrayList(u8).init(testing.allocator);
    defer output.deinit();
    try as.assemble(output.writer());
    try expectEqualHexStrings(expected, output.items, input);
}

test "assemble - Jcc" {
    const mnemonics = [_]struct { Instruction.Mnemonic, u8 }{
        .{ .ja, 0x87 },
        .{ .jae, 0x83 },
        .{ .jb, 0x82 },
        .{ .jbe, 0x86 },
        .{ .jc, 0x82 },
        .{ .je, 0x84 },
        .{ .jg, 0x8f },
        .{ .jge, 0x8d },
        .{ .jl, 0x8c },
        .{ .jle, 0x8e },
        .{ .jna, 0x86 },
        .{ .jnae, 0x82 },
        .{ .jnb, 0x83 },
        .{ .jnbe, 0x87 },
        .{ .jnc, 0x83 },
        .{ .jne, 0x85 },
        .{ .jng, 0x8e },
        .{ .jnge, 0x8c },
        .{ .jnl, 0x8d },
        .{ .jnle, 0x8f },
        .{ .jno, 0x81 },
        .{ .jnp, 0x8b },
        .{ .jns, 0x89 },
        .{ .jnz, 0x85 },
        .{ .jo, 0x80 },
        .{ .jp, 0x8a },
        .{ .jpe, 0x8a },
        .{ .jpo, 0x8b },
        .{ .js, 0x88 },
        .{ .jz, 0x84 },
    };

    inline for (&mnemonics) |mnemonic| {
        const input = @tagName(mnemonic[0]) ++ " 0x0";
        const expected = [_]u8{ 0x0f, mnemonic[1], 0x0, 0x0, 0x0, 0x0 };
        var as = Assembler.init(input);
        var output = std.ArrayList(u8).init(testing.allocator);
        defer output.deinit();
        try as.assemble(output.writer());
        try expectEqualHexStrings(&expected, output.items, input);
    }
}

test "assemble - SETcc" {
    const mnemonics = [_]struct { Instruction.Mnemonic, u8 }{
        .{ .seta, 0x97 },
        .{ .setae, 0x93 },
        .{ .setb, 0x92 },
        .{ .setbe, 0x96 },
        .{ .setc, 0x92 },
        .{ .sete, 0x94 },
        .{ .setg, 0x9f },
        .{ .setge, 0x9d },
        .{ .setl, 0x9c },
        .{ .setle, 0x9e },
        .{ .setna, 0x96 },
        .{ .setnae, 0x92 },
        .{ .setnb, 0x93 },
        .{ .setnbe, 0x97 },
        .{ .setnc, 0x93 },
        .{ .setne, 0x95 },
        .{ .setng, 0x9e },
        .{ .setnge, 0x9c },
        .{ .setnl, 0x9d },
        .{ .setnle, 0x9f },
        .{ .setno, 0x91 },
        .{ .setnp, 0x9b },
        .{ .setns, 0x99 },
        .{ .setnz, 0x95 },
        .{ .seto, 0x90 },
        .{ .setp, 0x9a },
        .{ .setpe, 0x9a },
        .{ .setpo, 0x9b },
        .{ .sets, 0x98 },
        .{ .setz, 0x94 },
    };

    inline for (&mnemonics) |mnemonic| {
        const input = @tagName(mnemonic[0]) ++ " al";
        const expected = [_]u8{ 0x0f, mnemonic[1], 0xC0 };
        var as = Assembler.init(input);
        var output = std.ArrayList(u8).init(testing.allocator);
        defer output.deinit();
        try as.assemble(output.writer());
        try expectEqualHexStrings(&expected, output.items, input);
    }
}

test "assemble - CMOVcc" {
    const mnemonics = [_]struct { Instruction.Mnemonic, u8 }{
        .{ .cmova, 0x47 },
        .{ .cmovae, 0x43 },
        .{ .cmovb, 0x42 },
        .{ .cmovbe, 0x46 },
        .{ .cmovc, 0x42 },
        .{ .cmove, 0x44 },
        .{ .cmovg, 0x4f },
        .{ .cmovge, 0x4d },
        .{ .cmovl, 0x4c },
        .{ .cmovle, 0x4e },
        .{ .cmovna, 0x46 },
        .{ .cmovnae, 0x42 },
        .{ .cmovnb, 0x43 },
        .{ .cmovnbe, 0x47 },
        .{ .cmovnc, 0x43 },
        .{ .cmovne, 0x45 },
        .{ .cmovng, 0x4e },
        .{ .cmovnge, 0x4c },
        .{ .cmovnl, 0x4d },
        .{ .cmovnle, 0x4f },
        .{ .cmovno, 0x41 },
        .{ .cmovnp, 0x4b },
        .{ .cmovns, 0x49 },
        .{ .cmovnz, 0x45 },
        .{ .cmovo, 0x40 },
        .{ .cmovp, 0x4a },
        .{ .cmovpe, 0x4a },
        .{ .cmovpo, 0x4b },
        .{ .cmovs, 0x48 },
        .{ .cmovz, 0x44 },
    };

    inline for (&mnemonics) |mnemonic| {
        const input = @tagName(mnemonic[0]) ++ " rax, rbx";
        const expected = [_]u8{ 0x48, 0x0f, mnemonic[1], 0xC3 };
        var as = Assembler.init(input);
        var output = std.ArrayList(u8).init(testing.allocator);
        defer output.deinit();
        try as.assemble(output.writer());
        try expectEqualHexStrings(&expected, output.items, input);
    }
}
