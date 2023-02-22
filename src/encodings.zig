const std = @import("std");
const assert = std.debug.assert;
const math = std.math;

const encoder = @import("encoder.zig");
const Instruction = encoder.Instruction;
const Rex = encoder.Rex;
const LegacyPrefixes = encoder.LegacyPrefixes;

const Entry = std.meta.Tuple(&.{ Mnemonic, OpEn, Operand, Operand, Operand, Operand, u2, u8, u8, u8, u3 });

// TODO move this into a .zon file when Zig is capable of importing .zon files
const table = &[_]Entry{
    .{ .adc, .i, .al, .imm8, .none, .none, 1, 0x14, 0x00, 0x00, 0 },
    .{ .adc, .i, .ax, .imm16, .none, .none, 1, 0x15, 0x00, 0x00, 0 },
    .{ .adc, .i, .eax, .imm32, .none, .none, 1, 0x15, 0x00, 0x00, 0 },
    .{ .adc, .i, .rax, .imm32, .none, .none, 1, 0x15, 0x00, 0x00, 0 },
    .{ .adc, .mi, .rm8, .imm8, .none, .none, 1, 0x80, 0x00, 0x00, 2 },
    .{ .adc, .mi, .rm16, .imm16, .none, .none, 1, 0x81, 0x00, 0x00, 2 },
    .{ .adc, .mi, .rm32, .imm32, .none, .none, 1, 0x81, 0x00, 0x00, 2 },
    .{ .adc, .mi, .rm64, .imm32, .none, .none, 1, 0x81, 0x00, 0x00, 2 },
    .{ .adc, .mi, .rm16, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 2 },
    .{ .adc, .mi, .rm32, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 2 },
    .{ .adc, .mi, .rm64, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 2 },
    .{ .adc, .mr, .rm8, .r8, .none, .none, 1, 0x10, 0x00, 0x00, 0 },
    .{ .adc, .mr, .rm16, .r16, .none, .none, 1, 0x11, 0x00, 0x00, 0 },
    .{ .adc, .mr, .rm32, .r32, .none, .none, 1, 0x11, 0x00, 0x00, 0 },
    .{ .adc, .mr, .rm64, .r64, .none, .none, 1, 0x11, 0x00, 0x00, 0 },
    .{ .adc, .rm, .r8, .rm8, .none, .none, 1, 0x12, 0x00, 0x00, 0 },
    .{ .adc, .rm, .r16, .rm16, .none, .none, 1, 0x13, 0x00, 0x00, 0 },
    .{ .adc, .rm, .r32, .rm32, .none, .none, 1, 0x13, 0x00, 0x00, 0 },
    .{ .adc, .rm, .r64, .rm64, .none, .none, 1, 0x13, 0x00, 0x00, 0 },

    .{ .add, .i, .al, .imm8, .none, .none, 1, 0x04, 0x00, 0x00, 0 },
    .{ .add, .i, .ax, .imm16, .none, .none, 1, 0x05, 0x00, 0x00, 0 },
    .{ .add, .i, .eax, .imm32, .none, .none, 1, 0x05, 0x00, 0x00, 0 },
    .{ .add, .i, .rax, .imm32, .none, .none, 1, 0x05, 0x00, 0x00, 0 },
    .{ .add, .mi, .rm8, .imm8, .none, .none, 1, 0x80, 0x00, 0x00, 0 },
    .{ .add, .mi, .rm16, .imm16, .none, .none, 1, 0x81, 0x00, 0x00, 0 },
    .{ .add, .mi, .rm32, .imm32, .none, .none, 1, 0x81, 0x00, 0x00, 0 },
    .{ .add, .mi, .rm64, .imm32, .none, .none, 1, 0x81, 0x00, 0x00, 0 },
    .{ .add, .mi, .rm16, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 0 },
    .{ .add, .mi, .rm32, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 0 },
    .{ .add, .mi, .rm64, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 0 },
    .{ .add, .mr, .rm8, .r8, .none, .none, 1, 0x00, 0x00, 0x00, 0 },
    .{ .add, .mr, .rm16, .r16, .none, .none, 1, 0x01, 0x00, 0x00, 0 },
    .{ .add, .mr, .rm32, .r32, .none, .none, 1, 0x01, 0x00, 0x00, 0 },
    .{ .add, .mr, .rm64, .r64, .none, .none, 1, 0x01, 0x00, 0x00, 0 },
    .{ .add, .rm, .r8, .rm8, .none, .none, 1, 0x02, 0x00, 0x00, 0 },
    .{ .add, .rm, .r16, .rm16, .none, .none, 1, 0x03, 0x00, 0x00, 0 },
    .{ .add, .rm, .r32, .rm32, .none, .none, 1, 0x03, 0x00, 0x00, 0 },
    .{ .add, .rm, .r64, .rm64, .none, .none, 1, 0x03, 0x00, 0x00, 0 },

    .{ .@"and", .i, .al, .imm8, .none, .none, 1, 0x24, 0x00, 0x00, 0 },
    .{ .@"and", .i, .ax, .imm16, .none, .none, 1, 0x25, 0x00, 0x00, 0 },
    .{ .@"and", .i, .eax, .imm32, .none, .none, 1, 0x25, 0x00, 0x00, 0 },
    .{ .@"and", .i, .rax, .imm32, .none, .none, 1, 0x25, 0x00, 0x00, 0 },
    .{ .@"and", .mi, .rm8, .imm8, .none, .none, 1, 0x80, 0x00, 0x00, 4 },
    .{ .@"and", .mi, .rm16, .imm16, .none, .none, 1, 0x81, 0x00, 0x00, 4 },
    .{ .@"and", .mi, .rm32, .imm32, .none, .none, 1, 0x81, 0x00, 0x00, 4 },
    .{ .@"and", .mi, .rm64, .imm32, .none, .none, 1, 0x81, 0x00, 0x00, 4 },
    .{ .@"and", .mi, .rm16, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 4 },
    .{ .@"and", .mi, .rm32, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 4 },
    .{ .@"and", .mi, .rm64, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 4 },
    .{ .@"and", .mr, .rm8, .r8, .none, .none, 1, 0x20, 0x00, 0x00, 0 },
    .{ .@"and", .mr, .rm16, .r16, .none, .none, 1, 0x21, 0x00, 0x00, 0 },
    .{ .@"and", .mr, .rm32, .r32, .none, .none, 1, 0x21, 0x00, 0x00, 0 },
    .{ .@"and", .mr, .rm64, .r64, .none, .none, 1, 0x21, 0x00, 0x00, 0 },
    .{ .@"and", .rm, .r8, .rm8, .none, .none, 1, 0x22, 0x00, 0x00, 0 },
    .{ .@"and", .rm, .r16, .rm16, .none, .none, 1, 0x23, 0x00, 0x00, 0 },
    .{ .@"and", .rm, .r32, .rm32, .none, .none, 1, 0x23, 0x00, 0x00, 0 },
    .{ .@"and", .rm, .r64, .rm64, .none, .none, 1, 0x23, 0x00, 0x00, 0 },

    .{ .call, .m, .rm64, .none, .none, .none, 1, 0xff, 0x00, 0x00, 2 },

    .{ .int3, .np, .none, .none, .none, .none, 1, 0xcc, 0x00, 0x00, 0 },

    .{ .lea, .rm, .r16, .m, .none, .none, 1, 0x8d, 0x00, 0x00, 0 },
    .{ .lea, .rm, .r32, .m, .none, .none, 1, 0x8d, 0x00, 0x00, 0 },
    .{ .lea, .rm, .r64, .m, .none, .none, 1, 0x8d, 0x00, 0x00, 0 },

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

    .{ .nop, .np, .none, .none, .none, .none, 1, 0x90, 0x00, 0x00, 0 },

    .{ .pop, .o, .r16, .none, .none, .none, 1, 0x58, 0x00, 0x00, 0 },
    .{ .pop, .o, .r64, .none, .none, .none, 1, 0x58, 0x00, 0x00, 0 },
    .{ .pop, .m, .rm16, .none, .none, .none, 1, 0x8f, 0x00, 0x00, 0 },
    .{ .pop, .m, .rm64, .none, .none, .none, 1, 0x8f, 0x00, 0x00, 0 },

    .{ .push, .o, .r16, .none, .none, .none, 1, 0x50, 0x00, 0x00, 0 },
    .{ .push, .o, .r64, .none, .none, .none, 1, 0x50, 0x00, 0x00, 0 },
    .{ .push, .m, .rm16, .none, .none, .none, 1, 0xff, 0x0, 0x00, 6 },
    .{ .push, .m, .rm64, .none, .none, .none, 1, 0xff, 0x0, 0x00, 6 },
    .{ .push, .i, .imm8, .none, .none, .none, 1, 0x6a, 0x00, 0x00, 0 },
    .{ .push, .i, .imm16, .none, .none, .none, 1, 0x68, 0x00, 0x00, 0 },
    .{ .push, .i, .imm32, .none, .none, .none, 1, 0x68, 0x00, 0x00, 0 },

    .{ .ret, .np, .none, .none, .none, .none, 1, 0xc3, 0x00, 0x00, 0 },

    .{ .syscall, .np, .none, .none, .none, .none, 2, 0x0f, 0x05, 0x00, 0 },
};

pub const Mnemonic = enum {
    // zig fmt: off
    adc, add, @"and",
    call, cmp,
    int3,
    lea,
    mov, movsx, movsxd,
    nop,
    @"or",
    pop, push,
    ret,
    sbb, sub, syscall,
    xor,
    // zig fmt: on

    pub fn defaultsTo64Bits(mnemonic: Mnemonic) bool {
        return switch (mnemonic) {
            .call, .push, .pop, .ret => true,
            else => false,
        };
    }
};

pub const OpEn = enum { np, o, i, m, fd, td, oi, mi, mr, rm };

/// TODO rename to something like Op or OperandClass to disambiguate from
/// Intruction.Operand storing actual input operands.
pub const Operand = enum {
    // zig fmt: off
    none,

    imm8, imm16, imm32, imm64,

    al, ax, eax, rax,

    r8, r16, r32, r64,

    rm8, rm16, rm32, rm64,

    m8, m16, m32, m64,

    m,

    moffs,

    sreg,
    // zig fmt: on

    pub fn fromOperand(operand: Instruction.Operand) Operand {
        switch (operand) {
            .none => return .none,

            .reg => |reg| {
                if (reg.isSegment()) return .sreg;

                const bit_size = reg.bitSize();
                if (reg.to64() == .rax) {
                    return switch (bit_size) {
                        8 => .al,
                        16 => .ax,
                        32 => .eax,
                        64 => .rax,
                        else => unreachable,
                    };
                } else {
                    return switch (bit_size) {
                        8 => .r8,
                        16 => .r16,
                        32 => .r32,
                        64 => .r64,
                        else => unreachable,
                    };
                }
            },

            .mem => |mem| {
                const bit_size = mem.bitSize();
                return switch (bit_size) {
                    8 => .m8,
                    16 => .m16,
                    32 => .m32,
                    64 => .m64,
                    else => unreachable,
                };
            },

            .moffs => return .moffs,

            .imm => |imm| {
                if (math.cast(u8, imm)) |_| return .imm8;
                if (math.cast(u16, imm)) |_| return .imm16;
                if (math.cast(u32, imm)) |_| return .imm32;
                return .imm64;
            },
        }
    }

    pub fn bitSize(op: Operand) u64 {
        return switch (op) {
            .none, .moffs, .m, .sreg => unreachable,
            .imm8, .al, .r8, .m8, .rm8 => 8,
            .imm16, .ax, .r16, .m16, .rm16 => 16,
            .imm32, .eax, .r32, .m32, .rm32 => 32,
            .imm64, .rax, .r64, .m64, .rm64 => 64,
        };
    }

    pub fn isRegister(op: Operand) bool {
        // zig fmt: off
        return switch (op) {
            .al, .ax, .eax, .rax,
            .r8, .r16, .r32, .r64,
            .rm8, .rm16, .rm32, .rm64,
            => return true,
            else => false,
        };
        // zig fmt: on
    }

    pub fn isImmediate(op: Operand) bool {
        return switch (op) {
            .imm8, .imm16, .imm32, .imm64 => return true,
            else => false,
        };
    }

    pub fn isMemory(op: Operand) bool {
        // zig fmt: off
        return switch (op) {
            .rm8, .rm16, .rm32, .rm64,
            .m8, .m16, .m32, .m64,
            .m,
            => return true,
            else => false,
        };
        // zig fmt: on
    }

    pub fn isSegment(op: Operand) bool {
        return switch (op) {
            .moffs, .sreg => return true,
            else => false,
        };
    }

    /// Given an operand `op` checks if `target` is a subset for the purposes
    /// of the encoding.
    pub fn isSubset(op: Operand, target: Operand) bool {
        switch (op) {
            .m => unreachable,
            .none, .moffs, .sreg => return op == target,
            else => {
                if (op.isRegister() and target.isRegister()) return op.bitSize() == target.bitSize();
                if (op.isMemory() and target.isMemory()) switch (target) {
                    .m => return true,
                    else => return op.bitSize() == target.bitSize(),
                };
                if (op.isImmediate() and target.isImmediate()) switch (target) {
                    .imm32 => switch (op) {
                        .imm8, .imm16, .imm32 => return true,
                        else => return op == target,
                    },
                    .imm16 => switch (op) {
                        .imm8, .imm16 => return true,
                        else => return op == target,
                    },
                    else => return op == target,
                };
                return false;
            },
        }
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
        op1: Instruction.Operand,
        op2: Instruction.Operand,
        op3: Instruction.Operand,
        op4: Instruction.Operand,
    }) ?Encoding {
        const input_op1 = Operand.fromOperand(args.op1);
        const input_op2 = Operand.fromOperand(args.op2);
        const input_op3 = Operand.fromOperand(args.op3);
        const input_op4 = Operand.fromOperand(args.op4);

        // TODO work out what is the maximum number of variants we can actually find in one swoop.
        var candidates: [10]Encoding = undefined;
        var count: usize = 0;
        inline for (table) |entry| {
            if (entry[0] == mnemonic and
                input_op1.isSubset(entry[2]) and
                input_op2.isSubset(entry[3]) and
                input_op3.isSubset(entry[4]) and
                input_op4.isSubset(entry[5]))
            {
                candidates[count] = Encoding{
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
                count += 1;
            }
        }

        if (count == 0) return null;
        if (count == 1) return candidates[0];

        const EncodingLength = struct {
            fn estimate(encoding: Encoding, params: struct {
                op1: Instruction.Operand,
                op2: Instruction.Operand,
                op3: Instruction.Operand,
                op4: Instruction.Operand,
            }) usize {
                var inst = Instruction{
                    .op1 = params.op1,
                    .op2 = params.op2,
                    .op3 = params.op3,
                    .op4 = params.op4,
                    .encoding = encoding,
                };
                var cwriter = std.io.countingWriter(std.io.null_writer);
                inst.encode(cwriter.writer()) catch unreachable;
                return cwriter.bytes_written;
            }
        };

        var shortest_encoding: ?struct {
            index: usize,
            len: usize,
        } = null;
        var i: usize = 0;
        while (i < count) : (i += 1) {
            const len = EncodingLength.estimate(candidates[i], .{
                .op1 = args.op1,
                .op2 = args.op2,
                .op3 = args.op3,
                .op4 = args.op4,
            });
            const current = shortest_encoding orelse {
                shortest_encoding = .{ .index = i, .len = len };
                continue;
            };
            if (len < current.len) {
                shortest_encoding = .{ .index = i, .len = len };
            }
        }

        return candidates[shortest_encoding.?.index];
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
            .i => {
                const op = if (encoding.op1.isImmediate()) encoding.op1 else encoding.op2;
                try writer.print("{s}", .{switch (op) {
                    .imm8 => "ib ",
                    .imm16 => "iw ",
                    .imm32 => "id ",
                    else => unreachable,
                }});
            },
            .m, .mi => try writer.print("/{d} ", .{encoding.modRmExt()}),
            .o => try writer.print("{s}", .{switch (encoding.op1) {
                .r8 => "+rb ",
                .r16 => "+rw ",
                .r32 => "+rd ",
                .r64 => "+rd ",
                else => unreachable,
            }}),
            .oi => try writer.print("{s}", .{switch (encoding.op1) {
                .r8 => "+rb ib ",
                .r16 => "+rw iw ",
                .r32 => "+rd id ",
                .r64 => "+rd io ",
                else => unreachable,
            }}),
            .rm, .mr => try writer.writeAll("/r "),
            .fd, .td => {},
            .np => {},
        }

        try writer.print("{s} ", .{@tagName(encoding.mnemonic)});

        for (&[_]Operand{ encoding.op1, encoding.op2, encoding.op3, encoding.op4 }) |op| {
            if (op == .none) break;
            try writer.print("{s} ", .{@tagName(op)});
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
// } 
// // zig fmt: on
// ++ genArithInst(.add, 0, 0) ++ genArithInst(.adc, 0x10, 2) ++ genArithInst(.@"and", 0x20, 4) ++
//     genArithInst(.cmp, 0x38, 7) ++ genArithInst(.@"or", 0x08, 1) ++ genArithInst(.sbb, 0x18, 3) ++
//     genArithInst(.sub, 0x28, 5) ++ genArithInst(.xor, 0x30, 6);
