const std = @import("std");
const assert = std.debug.assert;
const Rex = @import("encoder.zig").Rex;
const LegacyPrefixes = @import("encoder.zig").LegacyPrefixes;

const Entry = std.meta.Tuple(&.{ Mnemonic, OpEn, Operand, Operand, Operand, Operand, u2, u8, u8, u8, u3 });

// TODO move this into a .zon file when Zig is capable of importing .zon files
const table = &[_]Entry{
    .{ .mov, .mr, .rm8, .r8, .none, .none, 1, 0x88, 0x00, 0x00, 0 },
    .{ .mov, .mr, .rm16, .r16, .none, .none, 1, 0x89, 0x00, 0x00, 0 },
    .{ .mov, .mr, .rm32, .r32, .none, .none, 1, 0x89, 0x00, 0x00, 0 },
    .{ .mov, .mr, .rm64, .r64, .none, .none, 1, 0x89, 0x00, 0x00, 0 },
    .{ .mov, .rm, .r8, .rm8, .none, .none, 1, 0x8a, 0x00, 0x00, 0 },
    .{ .mov, .rm, .r16, .rm16, .none, .none, 1, 0x8b, 0x00, 0x00, 0 },
    .{ .mov, .rm, .r32, .rm32, .none, .none, 1, 0x8b, 0x00, 0x00, 0 },
    .{ .mov, .rm, .r64, .rm64, .none, .none, 1, 0x8b, 0x00, 0x00, 0 },
    // .{ .mov,     .mr, 16, 0,  0x8c, 0x00, 0x00 },
    // .{ .mov,     .mr, 64, 0,  0x8c, 0x00, 0x00 },
    // .{ .mov,     .rm, 0,  16, 0x8e, 0x00, 0x00 },
    // .{ .mov,     .rm, 0,  64, 0x8e, 0x00, 0x00 },
    .{ .mov, .fd, .al, .moffs, .none, .none, 1, 0xa0, 0x00, 0x00, 0 },
    .{ .mov, .fd, .ax, .moffs, .none, .none, 1, 0xa1, 0x00, 0x00, 0 },
    .{ .mov, .fd, .eax, .moffs, .none, .none, 1, 0xa1, 0x00, 0x00, 0 },
    .{ .mov, .fd, .rax, .moffs, .none, .none, 1, 0xa1, 0x00, 0x00, 0 },
    .{ .mov, .td, .moffs, .al, .none, .none, 1, 0xa2, 0x00, 0x00, 0 },
    .{ .mov, .td, .moffs, .ax, .none, .none, 1, 0xa3, 0x00, 0x00, 0 },
    .{ .mov, .td, .moffs, .eax, .none, .none, 1, 0xa3, 0x00, 0x00, 0 },
    .{ .mov, .td, .moffs, .rax, .none, .none, 1, 0xa3, 0x00, 0x00, 0 },
    .{ .mov, .oi, .r8, .imm8, .none, .none, 1, 0xb0, 0x00, 0x00, 0 },
    .{ .mov, .oi, .r16, .imm16, .none, .none, 1, 0xb8, 0x00, 0x00, 0 },
    .{ .mov, .oi, .r32, .imm32, .none, .none, 1, 0xb8, 0x00, 0x00, 0 },
    .{ .mov, .oi, .r64, .imm64, .none, .none, 1, 0xb8, 0x00, 0x00, 0 },
    .{ .mov, .mi, .rm8, .imm8, .none, .none, 1, 0xc6, 0x00, 0x00, 0 },
    .{ .mov, .mi, .rm16, .imm16, .none, .none, 1, 0xc7, 0x00, 0x00, 0 },
    .{ .mov, .mi, .rm32, .imm32, .none, .none, 1, 0xc7, 0x00, 0x00, 0 },
    .{ .mov, .mi, .rm64, .imm32, .none, .none, 1, 0xc7, 0x00, 0x00, 0 },

    .{ .movsx, .rm, .r16, .rm8, .none, .none, 2, 0x0f, 0xbe, 0x00, 0 },
    .{ .movsx, .rm, .r32, .rm8, .none, .none, 2, 0x0f, 0xbe, 0x00, 0 },
    .{ .movsx, .rm, .r64, .rm8, .none, .none, 2, 0x0f, 0xbe, 0x00, 0 },
    .{ .movsx, .rm, .r32, .rm16, .none, .none, 2, 0x0f, 0xbf, 0x00, 0 },
    .{ .movsx, .rm, .r64, .rm16, .none, .none, 2, 0x0f, 0xbf, 0x00, 0 },

    .{ .movsxd, .rm, .r64, .rm32, .none, .none, 1, 0x63, 0x00, 0x00, 0 },
};

pub const Mnemonic = enum {
    adc,
    add,
    @"and",
    cmp,
    @"or",
    sbb,
    sub,
    xor,
    lea,
    mov,
    movsx,
    movsxd,
    push,
    pop,
    call,
    int3,
    nop,
    ret,
    syscall,
};

pub const OpEn = enum {
    np,
    o,
    i,
    m,
    fd,
    td,
    oi,
    mi,
    mr,
    rm,
};

pub const Operand = enum {
    none,

    imm8,
    imm16,
    imm32,
    imm64,

    al,
    ax,
    eax,
    rax,

    r8,
    r16,
    r32,
    r64,

    rm8,
    rm16,
    rm32,
    rm64,

    moffs,

    sreg,

    fn bitSize(op: Operand) u64 {
        return switch (op) {
            .none, .moffs, .sreg => 0,
            .imm8, .al, .r8, .rm8 => 8,
            .imm16, .ax, .r16, .rm16 => 16,
            .imm32, .eax, .r32, .rm32 => 32,
            .imm64, .rax, .r64, .rm64 => 64,
        };
    }

    fn isMatch(op: Operand, other: Operand) bool {
        if (op == .rm8 and (other == .r8 or other == .al)) return true;
        if (op == .rm16 and (other == .r16 or other == .ax)) return true;
        if (op == .rm32 and (other == .r32 or other == .eax)) return true;
        if (op == .rm64 and (other == .r64 or other == .rax)) return true;
        if (op == .r8 and other == .al) return true;
        if (op == .r16 and other == .ax) return true;
        if (op == .r32 and other == .eax) return true;
        if (op == .r64 and other == .rax) return true;
        switch (op) {
            .imm32 => switch (other) {
                .imm8, .imm16, .imm32 => return true,
                else => {},
            },
            .imm16 => switch (other) {
                .imm8, .imm16 => return true,
                else => {},
            },
            else => {},
        }
        return op == other;
    }
};

pub const Encoding = struct {
    mnemonic: Mnemonic,
    op_en: OpEn,
    op1: Operand,
    op2: Operand,
    op3: Operand,
    op4: Operand,
    opc_len: u2,
    opc: [3]u8,
    modrm_ext: u3,

    pub fn findByMnemonic(mnemonic: Mnemonic, args: struct {
        op1: Operand = .none,
        op2: Operand = .none,
        op3: Operand = .none,
        op4: Operand = .none,
    }) ?Encoding {
        // TODO we should collect all matching variants and then select the shortest one
        inline for (table) |entry| {
            if (entry[0] == mnemonic and
                entry[2].isMatch(args.op1) and
                entry[3].isMatch(args.op2) and
                entry[4].isMatch(args.op3) and
                entry[5].isMatch(args.op4))
            {
                return Encoding{
                    .mnemonic = mnemonic,
                    .op_en = entry[1],
                    .op1 = entry[2],
                    .op2 = entry[3],
                    .op3 = entry[4],
                    .op4 = entry[5],
                    .opc_len = entry[6],
                    .opc = .{ entry[7], entry[8], entry[9] },
                    .modrm_ext = entry[10],
                };
            }
        }

        return null;
    }

    pub fn findByOpcode(opc: [3]u8) ?Encoding {
        inline for (table) |entry| {
            if (entry[6] == opc[0] and entry[7] == opc[1] and entry[8] == opc[2]) {
                return .{
                    .mnemonic = entry[0],
                    .op_en = entry[1],
                    .op1 = .none,
                    .op2 = .none,
                    .op3 = .none,
                    .op4 = .none,
                    .opc_len = entry[6],
                    .opc = .{ entry[7], entry[8], entry[9] },
                    .modrm_ext = entry[10],
                };
            }
        }
        return null;
    }

    pub fn opcode(encoding: *const Encoding) []const u8 {
        return encoding.opc[0..encoding.opc_len];
    }

    pub fn modRmExt(encoding: Encoding) u3 {
        assert(encoding.op_en == .m or encoding.op_en == .mi);
        return encoding.modrm_ext;
    }

    pub fn format(
        encoding: Encoding,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = options;
        _ = fmt;
        for (encoding.opcode()) |byte| {
            try writer.print("{x:0>2} ", .{byte});
        }

        switch (encoding.op_en) {
            .mi => try writer.print("/{d} ", .{encoding.modRmExt()}),
            .oi => try writer.print("{s}", .{switch (encoding.op1) {
                .r8 => "+rb ib ",
                .r16 => "+rw iw ",
                .r32 => "+rd id ",
                .r64 => "+rd io ",
                else => unreachable,
            }}),
            .rm, .mr => try writer.writeAll("/r "),
            .fd, .td => {},
            else => {},
        }

        try writer.print("{s} ", .{@tagName(encoding.mnemonic)});

        switch (encoding.op_en) {
            .mi,
            .oi,
            .fd,
            .td,
            .rm,
            .mr,
            => try writer.print("{s} {s} ", .{ @tagName(encoding.op1), @tagName(encoding.op2) }),

            else => {},
        }

        try writer.print("{s}", .{@tagName(encoding.op_en)});
    }
};

// fn genArithInst(comptime tag: Tag, op_add: u8, modrm_ext: u8) [19]Entry {
//     // zig fmt: off
//     return [_]Entry{
//         .{ tag, .i,  8,  8,  op_add + 0x04, 0x00,      0x00 },
//         .{ tag, .i,  16, 16, op_add + 0x05, 0x00,      0x00 },
//         .{ tag, .i,  32, 32, op_add + 0x05, 0x00,      0x00 },
//         .{ tag, .i,  64, 32, op_add + 0x05, 0x00,      0x00 },
//         .{ tag, .mi, 8,  8,           0x80, modrm_ext, 0x00 },
//         .{ tag, .mi, 16, 16,          0x81, modrm_ext, 0x00 },
//         .{ tag, .mi, 32, 32,          0x81, modrm_ext, 0x00 },
//         .{ tag, .mi, 64, 32,          0x81, modrm_ext, 0x00 },
//         .{ tag, .mi, 16, 8,           0x83, modrm_ext, 0x00 },
//         .{ tag, .mi, 32, 8,           0x83, modrm_ext, 0x00 },
//         .{ tag, .mi, 64, 8,           0x83, modrm_ext, 0x00 },
//         .{ tag, .mr, 8,  8,  op_add + 0x00, 0x00,      0x00 },
//         .{ tag, .mr, 16, 16, op_add + 0x01, 0x00,      0x00 },
//         .{ tag, .mr, 32, 32, op_add + 0x01, 0x00,      0x00 },
//         .{ tag, .mr, 64, 64, op_add + 0x01, 0x00,      0x00 },
//         .{ tag, .rm, 8,  8,  op_add + 0x02, 0x00,      0x00 },
//         .{ tag, .rm, 16, 16, op_add + 0x03, 0x00,      0x00 },
//         .{ tag, .rm, 32, 32, op_add + 0x03, 0x00,      0x00 },
//         .{ tag, .rm, 64, 64, op_add + 0x03, 0x00,      0x00 },
//     };
//     // zig fmt: on
// }

// zig fmt: off
// pub const table = [_]Entry{
//     .{ .call,    .m,  16, 0,  0xe8, 0x00, 0x00 },
//     .{ .call,    .m,  32, 0,  0xe8, 0x00, 0x00 },
//     .{ .call,    .m,  64, 0,  0xff, 0x02, 0x00 },

//     .{ .lea,     .rm, 16, 32, 0x8d, 0x00, 0x00 },
//     .{ .lea,     .rm, 16, 64, 0x8d, 0x00, 0x00 },
//     .{ .lea,     .rm, 32, 32, 0x8d, 0x00, 0x00 },
//     .{ .lea,     .rm, 32, 64, 0x8d, 0x00, 0x00 },
//     .{ .lea,     .rm, 64, 32, 0x8d, 0x00, 0x00 },
//     .{ .lea,     .rm, 64, 64, 0x8d, 0x00, 0x00 },

//     .{ .mov,     .mr, 8,  8,  0x88, 0x00, 0x00 },
//     .{ .mov,     .mr, 16, 16, 0x89, 0x00, 0x00 },
//     .{ .mov,     .mr, 32, 32, 0x89, 0x00, 0x00 },
//     .{ .mov,     .mr, 64, 64, 0x89, 0x00, 0x00 },
//     .{ .mov,     .rm, 8,  8,  0x8a, 0x00, 0x00 },
//     .{ .mov,     .rm, 16, 16, 0x8b, 0x00, 0x00 },
//     .{ .mov,     .rm, 32, 32, 0x8b, 0x00, 0x00 },
//     .{ .mov,     .rm, 64, 64, 0x8b, 0x00, 0x00 },
//     .{ .mov,     .mr, 16, 0,  0x8c, 0x00, 0x00 },
//     .{ .mov,     .mr, 64, 0,  0x8c, 0x00, 0x00 },
//     .{ .mov,     .rm, 0,  16, 0x8e, 0x00, 0x00 },
//     .{ .mov,     .rm, 0,  64, 0x8e, 0x00, 0x00 },
//     .{ .mov,     .fd, 8,  8,  0xa0, 0x00, 0x00 },
//     .{ .mov,     .fd, 16, 16, 0xa1, 0x00, 0x00 },
//     .{ .mov,     .fd, 32, 32, 0xa1, 0x00, 0x00 },
//     .{ .mov,     .fd, 64, 64, 0xa1, 0x00, 0x00 },
//     .{ .mov,     .td, 8,  8,  0xa2, 0x00, 0x00 },
//     .{ .mov,     .td, 16, 16, 0xa3, 0x00, 0x00 },
//     .{ .mov,     .td, 32, 32, 0xa3, 0x00, 0x00 },
//     .{ .mov,     .td, 64, 64, 0xa3, 0x00, 0x00 },
//     .{ .mov,     .oi, 8,  8,  0xb0, 0x00, 0x00 },
//     .{ .mov,     .oi, 16, 16, 0xb8, 0x00, 0x00 },
//     .{ .mov,     .oi, 32, 32, 0xb8, 0x00, 0x00 },
//     .{ .mov,     .oi, 64, 64, 0xb8, 0x00, 0x00 },
//     .{ .mov,     .mi, 8,  8,  0xc6, 0x00, 0x00 },
//     .{ .mov,     .mi, 16, 16, 0xc7, 0x00, 0x00 },
//     .{ .mov,     .mi, 32, 32, 0xc7, 0x00, 0x00 },
//     .{ .mov,     .mi, 64, 32, 0xc7, 0x00, 0x00 },

//     .{ .movsx,   .rm, 16, 8,  0x0f, 0xbe, 0x00 },
//     .{ .movsx,   .rm, 32, 8,  0x0f, 0xbe, 0x00 },
//     .{ .movsx,   .rm, 64, 8,  0x0f, 0xbe, 0x00 },
//     .{ .movsx,   .rm, 32, 16, 0x0f, 0xbf, 0x00 },
//     .{ .movsx,   .rm, 64, 16, 0x0f, 0xbf, 0x00 },

//     .{ .movsxd,  .rm, 64, 32, 0x63, 0x00, 0x00 },

//     .{ .int3,    .np, 0,  0,  0xcc, 0x00, 0x00 },

//     .{ .nop,     .np, 0,  0,  0x90, 0x00, 0x00 },

//     .{ .pop,     .m,  16, 0,  0x8f, 0x00, 0x00 },
//     .{ .pop,     .m,  64, 0,  0x8f, 0x00, 0x00 },
//     .{ .pop,     .o,  16, 0,  0x58, 0x00, 0x00 },
//     .{ .pop,     .o,  64, 0,  0x58, 0x00, 0x00 },

//     .{ .push,    .m,  16, 0,  0xff, 0x06, 0x00 },
//     .{ .push,    .m,  64, 0,  0xff, 0x06, 0x00 },
//     .{ .push,    .o,  16, 0,  0x50, 0x00, 0x00 },
//     .{ .push,    .o,  64, 0,  0x50, 0x00, 0x00 },
//     .{ .push,    .i,  8,  0,  0x6a, 0x00, 0x00 },
//     .{ .push,    .i,  16, 0,  0x68, 0x00, 0x00 },
//     .{ .push,    .i,  32, 0,  0x68, 0x00, 0x00 },

//     .{ .ret,     .np, 0,  0,  0xc3, 0x00, 0x00 },

//     .{ .syscall, .np, 0,  0,  0x0f, 0x05, 0x00 },
// } 
// // zig fmt: on
// ++ genArithInst(.add, 0, 0) ++ genArithInst(.adc, 0x10, 2) ++ genArithInst(.@"and", 0x20, 4) ++
//     genArithInst(.cmp, 0x38, 7) ++ genArithInst(.@"or", 0x08, 1) ++ genArithInst(.sbb, 0x18, 3) ++
//     genArithInst(.sub, 0x28, 5) ++ genArithInst(.xor, 0x30, 6);
