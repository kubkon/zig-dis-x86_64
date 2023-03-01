const Encoding = @This();

const std = @import("std");
const assert = std.debug.assert;
const math = std.math;

const bits = @import("bits.zig");
const encoder = @import("encoder.zig");
const Instruction = encoder.Instruction;
const Register = bits.Register;
const Rex = encoder.Rex;
const LegacyPrefixes = encoder.LegacyPrefixes;

const table = @import("encodings.zig").table;

mnemonic: Mnemonic,
op_en: OpEn,
op1: Op,
op2: Op,
op3: Op,
op4: Op,
opc_len: u2,
opc: [3]u8,
modrm_ext: u3,
prefix: Prefix,

pub fn findByMnemonic(mnemonic: Mnemonic, args: struct {
    op1: Instruction.Operand,
    op2: Instruction.Operand,
    op3: Instruction.Operand,
    op4: Instruction.Operand,
}) ?Encoding {
    const input_op1 = Op.fromOperand(args.op1);
    const input_op2 = Op.fromOperand(args.op2);
    const input_op3 = Op.fromOperand(args.op3);
    const input_op4 = Op.fromOperand(args.op4);

    // TODO work out what is the maximum number of variants we can actually find in one swoop.
    var candidates: [10]Encoding = undefined;
    var count: usize = 0;
    inline for (table) |entry| {
        const enc = Encoding{
            .mnemonic = entry[0],
            .op_en = entry[1],
            .op1 = entry[2],
            .op2 = entry[3],
            .op3 = entry[4],
            .op4 = entry[5],
            .opc_len = entry[6],
            .opc = .{ entry[7], entry[8], entry[9] },
            .modrm_ext = entry[10],
            .prefix = entry[11],
        };
        if (enc.mnemonic == mnemonic and
            input_op1.isSubset(enc.op1) and
            input_op2.isSubset(enc.op2) and
            input_op3.isSubset(enc.op3) and
            input_op4.isSubset(enc.op4))
        {
            candidates[count] = enc;
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

/// Returns first matching encoding by opcode.
pub fn findByOpcode(opc: []const u8, prefixes: struct {
    legacy: LegacyPrefixes,
    rex: Rex,
}, modrm_ext: ?u3) ?Encoding {
    inline for (table) |entry| {
        const enc = Encoding{
            .mnemonic = entry[0],
            .op_en = entry[1],
            .op1 = entry[2],
            .op2 = entry[3],
            .op3 = entry[4],
            .op4 = entry[5],
            .opc_len = entry[6],
            .opc = .{ entry[7], entry[8], entry[9] },
            .modrm_ext = entry[10],
            .prefix = entry[11],
        };
        const match = match: {
            if (modrm_ext) |ext| {
                break :match ext == enc.modrm_ext and std.mem.eql(u8, enc.opcode(), opc);
            }
            break :match std.mem.eql(u8, enc.opcode(), opc);
        };
        if (match) {
            if (prefixes.rex.w) {
                if (enc.prefix == .rex_w) return enc;
            } else if (prefixes.legacy.prefix_66) {
                if (enc.prefix == .p_66h) return enc;
            } else {
                if (enc.prefix == .none) {
                    const bit_size = switch (enc.op_en) {
                        .i, .np => return enc,
                        .td => enc.op2.bitSize(),
                        else => enc.op1.bitSize(),
                    };
                    if (bit_size != 16) return enc;
                }
            }
        }
    }
    return null;
}

pub fn opcode(encoding: *const Encoding) []const u8 {
    return encoding.opc[0..encoding.opc_len];
}

pub fn modRmExt(encoding: Encoding) u3 {
    return switch (encoding.op_en) {
        .m, .mi, .m1, .mc => encoding.modrm_ext,
        else => unreachable,
    };
}

pub fn format(
    encoding: Encoding,
    comptime fmt: []const u8,
    options: std.fmt.FormatOptions,
    writer: anytype,
) !void {
    _ = options;
    _ = fmt;
    switch (encoding.prefix) {
        .rex_w => try writer.writeAll("REX.W + "),
        else => {},
    }

    for (encoding.opcode()) |byte| {
        try writer.print("{x:0>2} ", .{byte});
    }

    switch (encoding.op_en) {
        .np, .fd, .td, .i, .zi, .d => {},
        .o, .oi => {
            const tag = switch (encoding.op1) {
                .r8 => "rb",
                .r16 => "rw",
                .r32 => "rd",
                .r64 => "rd",
                else => unreachable,
            };
            try writer.print("+{s} ", .{tag});
        },
        .m, .mi, .m1, .mc => try writer.print("/{d} ", .{encoding.modRmExt()}),
        .mr, .rm, .rmi => try writer.writeAll("/r "),
    }

    switch (encoding.op_en) {
        .i, .d, .zi, .oi, .mi, .rmi => {
            const op = switch (encoding.op_en) {
                .i, .d => encoding.op1,
                .zi, .oi, .mi => encoding.op2,
                .rmi => encoding.op3,
                else => unreachable,
            };
            const tag = switch (op) {
                .imm8 => "ib",
                .imm16 => "iw",
                .imm32 => "id",
                .imm64 => "io",
                .rel8 => "cb",
                .rel16 => "cw",
                .rel32 => "cd",
                else => unreachable,
            };
            try writer.print("{s} ", .{tag});
        },
        .np, .fd, .td, .o, .m, .m1, .mc, .mr, .rm => {},
    }

    try writer.print("{s} ", .{@tagName(encoding.mnemonic)});

    const ops = &[_]Op{ encoding.op1, encoding.op2, encoding.op3, encoding.op4 };
    for (ops) |op| {
        if (op == .none) break;
        try writer.print("{s} ", .{@tagName(op)});
    }

    const op_en = switch (encoding.op_en) {
        .zi => .i,
        else => |op_en| op_en,
    };
    try writer.print("{s}", .{@tagName(op_en)});
}

pub const Mnemonic = enum {
    // zig fmt: off
    adc, add, @"and",
    call, cbw, cwde, cdqe, cwd, cdq, cqo, cmp,
    cmova, cmovae, cmovb, cmovbe, cmovc, cmove, cmovg, cmovge, cmovl, cmovle, cmovna,
    cmovnae, cmovnb, cmovnbe, cmovnc, cmovne, cmovng, cmovnge, cmovnl, cmovnle, cmovno,
    cmovnp, cmovns, cmovnz, cmovo, cmovp, cmovpe, cmovpo, cmovs, cmovz,
    div,
    idiv, imul, int3,
    ja, jae, jb, jbe, jc, jrcxz, je, jg, jge, jl, jle, jna, jnae, jnb, jnbe,
    jnc, jne, jng, jnge, jnl, jnle, jno, jnp, jns, jnz, jo, jp, jpe, jpo, js, jz,
    jmp, 
    lea,
    mov, movsx, movsxd, movzx, mul,
    nop,
    @"or",
    pop, push,
    ret,
    sal, sar, sbb, shl, shr, sub, syscall,
    seta, setae, setb, setbe, setc, sete, setg, setge, setl, setle, setna, setnae,
    setnb, setnbe, setnc, setne, setng, setnge, setnl, setnle, setno, setnp, setns,
    setnz, seto, setp, setpe, setpo, sets, setz,
    @"test",
    xor,
    // zig fmt: on
};

pub const OpEn = enum {
    // zig fmt: off
    np,
    o, oi,
    i, zi,
    d, m,
    fd, td,
    m1, mc, mi, mr, rm, rmi,
    // zig fmt: on
};

pub const Op = enum {
    // zig fmt: off
    none,
    unity,
    imm8, imm16, imm32, imm64,
    al, ax, eax, rax,
    cl,
    r8, r16, r32, r64,
    rm8, rm16, rm32, rm64,
    m8, m16, m32, m64,
    rel8, rel16, rel32,
    m,
    moffs,
    sreg,
    // zig fmt: on

    pub fn fromOperand(operand: Instruction.Operand) Op {
        switch (operand) {
            .none => return .none,

            .reg => |reg| {
                if (reg.isSegment()) return .sreg;
                if (reg.to64() == .rax) return switch (reg) {
                    .al => .al,
                    .ax => .ax,
                    .eax => .eax,
                    .rax => .rax,
                    else => unreachable,
                };
                if (reg == .cl) return .cl;
                return switch (reg.bitSize()) {
                    8 => .r8,
                    16 => .r16,
                    32 => .r32,
                    64 => .r64,
                    else => unreachable,
                };
            },

            .mem => |mem| switch (mem) {
                .moffs => return .moffs,
                .sib, .rip => {
                    const bit_size = mem.bitSize();
                    return switch (bit_size) {
                        8 => .m8,
                        16 => .m16,
                        32 => .m32,
                        64 => .m64,
                        else => unreachable,
                    };
                },
            },

            .imm => |imm| {
                if (imm == 1) return .unity;
                if (math.cast(i8, imm)) |_| return .imm8;
                if (math.cast(i16, imm)) |_| return .imm16;
                if (math.cast(i32, imm)) |_| return .imm32;
                return .imm64;
            },
        }
    }

    pub fn bitSize(op: Op) u64 {
        return switch (op) {
            .none, .moffs, .m, .sreg, .unity => unreachable,
            .imm8, .al, .cl, .r8, .m8, .rm8, .rel8 => 8,
            .imm16, .ax, .r16, .m16, .rm16, .rel16 => 16,
            .imm32, .eax, .r32, .m32, .rm32, .rel32 => 32,
            .imm64, .rax, .r64, .m64, .rm64 => 64,
        };
    }

    pub fn isRegister(op: Op) bool {
        // zig fmt: off
        return switch (op) {
            .cl,
            .al, .ax, .eax, .rax,
            .r8, .r16, .r32, .r64,
            .rm8, .rm16, .rm32, .rm64,
            => return true,
            else => false,
        };
        // zig fmt: on
    }

    pub fn isImmediate(op: Op) bool {
        // zig fmt: off
        return switch (op) {
            .imm8, .imm16, .imm32, .imm64, 
            .rel8, .rel16, .rel32,
            .unity,
            => return true,
            else => false,
        };
        // zig fmt: on
    }

    pub fn isMemory(op: Op) bool {
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

    pub fn isSegment(op: Op) bool {
        return switch (op) {
            .moffs, .sreg => return true,
            else => false,
        };
    }

    /// Given an operand `op` checks if `target` is a subset for the purposes
    /// of the encoding.
    pub fn isSubset(op: Op, target: Op) bool {
        switch (op) {
            .m => unreachable,
            .none, .moffs, .sreg => return op == target,
            else => {
                if (op.isRegister() and target.isRegister()) switch (target) {
                    .cl, .al, .ax, .eax, .rax => return op == target,
                    else => return op.bitSize() == target.bitSize(),
                };
                if (op.isMemory() and target.isMemory()) switch (target) {
                    .m => return true,
                    else => return op.bitSize() == target.bitSize(),
                };
                if (op.isImmediate() and target.isImmediate()) switch (target) {
                    .imm32, .rel32 => switch (op) {
                        .unity, .imm8, .imm16, .imm32 => return true,
                        else => return op == target,
                    },
                    .imm16, .rel16 => switch (op) {
                        .unity, .imm8, .imm16 => return true,
                        else => return op == target,
                    },
                    .imm8, .rel8 => switch (op) {
                        .unity, .imm8 => return true,
                        else => return op == target,
                    },
                    else => return op == target,
                };
                return false;
            },
        }
    }
};

pub const Prefix = enum {
    none,
    rex_w,
    p_66h,
};
