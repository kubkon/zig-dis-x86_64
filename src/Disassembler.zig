const Disassembler = @This();

const std = @import("std");
const assert = std.debug.assert;
const math = std.math;

const bits = @import("bits.zig");
const encoder = @import("encoder.zig");
const encodings = @import("encodings.zig");

const Encoding = encodings.Encoding;
const Instruction = encoder.Instruction;
const LegacyPrefixes = encoder.LegacyPrefixes;
const Memory = bits.Memory;
const Mnemonic = encodings.Mnemonic;
const Register = bits.Register;
const Rex = encoder.Rex;

pub const Error = error{
    EndOfStream,
    LegacyPrefixAfterRex,
    InvalidModRmByte,
    InvalidRexForEncoding,
    UnknownOpcode,
    Todo,
};

code: []const u8,
pos: usize = 0,

pub fn init(code: []const u8) Disassembler {
    return .{ .code = code };
}

pub fn next(dis: *Disassembler) Error!?Instruction {
    const prefixes = dis.parsePrefixes() catch |err| switch (err) {
        error.EndOfStream => return null,
        else => |e| return e,
    };

    const encoding = try dis.parseEncoding(prefixes) orelse return error.UnknownOpcode;
    switch (encoding.op_en) {
        .oi, .zi => {
            const reg_low_enc = @truncate(u3, dis.code[dis.pos - 1]);
            const imm = try dis.parseImm(encoding.op2);
            return Instruction{
                .op1 = .{ .reg = Register.gpFromLowEnc(reg_low_enc, prefixes.rex.b, encoding.op1.bitSize()) },
                .op2 = .{ .imm = imm },
                .encoding = encoding,
            };
        },
        .mr => {
            const modrm = try dis.parseModRmByte();
            const sib = if (modrm.sib()) try dis.parseSibByte() else null;

            if (modrm.direct()) {
                return Instruction{
                    .op1 = .{ .reg = Register.gpFromLowEnc(modrm.op2, prefixes.rex.b, encoding.op1.bitSize()) },
                    .op2 = .{ .reg = Register.gpFromLowEnc(modrm.op1, prefixes.rex.x, encoding.op2.bitSize()) },
                    .encoding = encoding,
                };
            }

            const disp = try dis.parseDisplacement(modrm, sib);

            if (modrm.rip()) {
                return Instruction{
                    .op1 = .{ .mem = Memory.rip(Memory.PtrSize.fromBitSize(encoding.op1.bitSize()), disp) },
                    .op2 = .{ .reg = Register.gpFromLowEnc(modrm.op1, prefixes.rex.r, encoding.op2.bitSize()) },
                    .encoding = encoding,
                };
            }

            const scale_index = if (sib) |info| info.scaleIndex(prefixes.rex) else null;
            const base = if (sib) |info|
                info.baseReg(modrm, prefixes)
            else
                Register.gpFromLowEnc(modrm.op2, prefixes.rex.b, 64);
            const reg = Register.gpFromLowEnc(modrm.op1, prefixes.rex.r, encoding.op2.bitSize());
            return Instruction{
                .op1 = .{ .mem = Memory.sib(Memory.PtrSize.fromBitSize(encoding.op1.bitSize()), .{
                    .base = base,
                    .scale_index = scale_index,
                    .disp = disp,
                }) },
                .op2 = .{ .reg = reg },
                .encoding = encoding,
            };
        },
        else => return error.Todo,
    }
}

const Prefixes = struct {
    legacy: LegacyPrefixes = .{},
    rex: Rex = .{},
    // TODO add support for VEX prefix
};

fn parsePrefixes(dis: *Disassembler) !Prefixes {
    const rex_prefix_mask: u8 = 0b0100_0000;
    var stream = std.io.fixedBufferStream(dis.code[dis.pos..]);
    const reader = stream.reader();

    var res: Prefixes = .{};
    var has_rex = false;

    while (true) {
        const next_byte = try reader.readByte();
        dis.pos += 1;

        switch (next_byte) {
            0xf0, 0xf2, 0xf3, 0x2e, 0x36, 0x26, 0x64, 0x65, 0x3e, 0x66, 0x67 => {
                // Legacy prefix
                if (has_rex) return error.LegacyPrefixAfterRex;
                switch (next_byte) {
                    0xf0 => res.legacy.prefix_f0 = true,
                    0xf2 => res.legacy.prefix_f2 = true,
                    0xf3 => res.legacy.prefix_f3 = true,
                    0x2e => res.legacy.prefix_2e = true,
                    0x36 => res.legacy.prefix_36 = true,
                    0x26 => res.legacy.prefix_26 = true,
                    0x64 => res.legacy.prefix_64 = true,
                    0x65 => res.legacy.prefix_65 = true,
                    0x3e => res.legacy.prefix_3e = true,
                    0x66 => res.legacy.prefix_66 = true,
                    0x67 => res.legacy.prefix_67 = true,
                    else => unreachable,
                }
            },
            else => {
                if (rex_prefix_mask & next_byte != 0) {
                    // REX prefix
                    res.rex.w = next_byte & 0b1000 != 0;
                    res.rex.r = next_byte & 0b100 != 0;
                    res.rex.x = next_byte & 0b10 != 0;
                    res.rex.b = next_byte & 0b1 != 0;
                    has_rex = true;
                    continue;
                }

                // TODO VEX prefix

                dis.pos -= 1;
                break;
            },
        }
    }

    return res;
}

fn parseEncoding(dis: *Disassembler, prefixes: Prefixes) !?Encoding {
    const o_mask: u8 = 0b1111_1000;

    var opcode: [3]u8 = .{ 0, 0, 0 };
    var stream = std.io.fixedBufferStream(dis.code[dis.pos..]);
    const reader = stream.reader();

    comptime var opc_count = 0;
    inline while (opc_count < 3) : (opc_count += 1) {
        const byte = try reader.readByte();
        dis.pos += 1;

        if (byte == 0x0f) {
            // Multi-byte opcode
            opcode[opc_count] = byte;
        } else if (opc_count > 1) {
            // Multi-byte opcode
            return error.Todo;
        } else {
            opcode[opc_count] = byte;
            // Single-byte opcode
            if (Encoding.findByOpcode(opcode[0..1], .{
                .legacy = prefixes.legacy,
                .rex = prefixes.rex,
            })) |mnemonic| {
                return mnemonic;
            } else {
                // Try O* encoding
                return Encoding.findByOpcode(&.{opcode[0] & o_mask}, .{
                    .legacy = prefixes.legacy,
                    .rex = prefixes.rex,
                });
            }
        }
    }
    return null;
}

fn parseImm(dis: *Disassembler, kind: encodings.Op) !i64 {
    var stream = std.io.fixedBufferStream(dis.code[dis.pos..]);
    var creader = std.io.countingReader(stream.reader());
    const reader = creader.reader();
    const imm = switch (kind) {
        .imm8 => try reader.readInt(i8, .Little),
        .imm16 => try reader.readInt(i16, .Little),
        .imm32 => try reader.readInt(i32, .Little),
        .imm64 => try reader.readInt(i64, .Little),
        else => unreachable,
    };
    dis.pos += creader.bytes_read;
    return imm;
}

const ModRm = packed struct {
    mod: u2,
    op1: u3,
    op2: u3,

    inline fn direct(self: ModRm) bool {
        return self.mod == 0b11;
    }

    inline fn rip(self: ModRm) bool {
        return self.mod == 0 and self.op2 == 0b101;
    }

    inline fn sib(self: ModRm) bool {
        return !self.direct() and self.op2 == 0b100;
    }
};

fn parseModRmByte(dis: *Disassembler) !ModRm {
    if (dis.code[dis.pos..].len == 0) return error.EndOfStream;
    const modrm_byte = dis.code[dis.pos];
    dis.pos += 1;
    const mod: u2 = @truncate(u2, modrm_byte >> 6);
    const op1: u3 = @truncate(u3, modrm_byte >> 3);
    const op2: u3 = @truncate(u3, modrm_byte);
    return ModRm{ .mod = mod, .op1 = op1, .op2 = op2 };
}

const Sib = packed struct {
    scale: u2,
    index: u3,
    base: u3,

    fn scaleIndex(self: Sib, rex: Rex) ?Memory.ScaleIndex {
        if (self.index == 0b100 and !rex.x) return null;
        return .{
            .scale = @as(u4, 1) << self.scale,
            .index = Register.gpFromLowEnc(self.index, rex.x, 64),
        };
    }

    fn baseReg(self: Sib, modrm: ModRm, prefixes: Prefixes) ?Register {
        if (self.base == 0b101 and modrm.mod == 0) {
            if (self.scaleIndex(prefixes.rex)) |_| return null;
            // Segment register
            if (prefixes.legacy.prefix_2e) return .cs;
            if (prefixes.legacy.prefix_36) return .ss;
            if (prefixes.legacy.prefix_26) return .es;
            if (prefixes.legacy.prefix_64) return .fs;
            if (prefixes.legacy.prefix_65) return .gs;
            return .ds;
        }
        return Register.gpFromLowEnc(self.base, prefixes.rex.b, 64);
    }
};

fn parseSibByte(dis: *Disassembler) !Sib {
    if (dis.code[dis.pos..].len == 0) return error.EndOfStream;
    const sib_byte = dis.code[dis.pos];
    dis.pos += 1;
    const scale: u2 = @truncate(u2, sib_byte >> 6);
    const index: u3 = @truncate(u3, sib_byte >> 3);
    const base: u3 = @truncate(u3, sib_byte);
    return Sib{ .scale = scale, .index = index, .base = base };
}

fn parseDisplacement(dis: *Disassembler, modrm: ModRm, sib: ?Sib) !i32 {
    var stream = std.io.fixedBufferStream(dis.code[dis.pos..]);
    var creader = std.io.countingReader(stream.reader());
    const reader = creader.reader();
    const disp = disp: {
        if (sib) |info| {
            if (info.base == 0b101 and modrm.mod == 0) {
                break :disp try reader.readInt(i32, .Little);
            }
        }
        if (modrm.rip()) {
            break :disp try reader.readInt(i32, .Little);
        }
        break :disp switch (modrm.mod) {
            0b01 => try reader.readInt(i8, .Little),
            0b10 => try reader.readInt(i32, .Little),
            else => unreachable,
        };
    };
    dis.pos += creader.bytes_read;
    return disp;
}
