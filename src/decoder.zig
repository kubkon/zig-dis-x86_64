const std = @import("std");
const assert = std.debug.assert;
const math = std.math;

const bits = @import("bits.zig");
const encoder = @import("encoder.zig");

const Instruction = encoder.Instruction;
const LegacyPrefixes = encoder.LegacyPrefixes;
const Memory = bits.Memory;
const Register = bits.Register;
const RegisterOrMemory = bits.RegisterOrMemory;
const Rex = encoder.Rex;

const Allocator = std.mem.Allocator;

pub const Error = error{
    EndOfStream,
    InvalidModRmByte,
    InvalidRexForEncoding,
    Todo,
};

pub const Disassembler = struct {
    code: []const u8,
    stream: std.io.FixedBufferStream([]const u8),

    pub fn init(code: []const u8) Disassembler {
        return .{
            .code = code,
            .stream = std.io.fixedBufferStream(code),
        };
    }

    pub fn next(self: *Disassembler) Error!?Instruction {
        const prefixes = parseLegacyPrefixes(&self.stream) catch |err| switch (err) {
            error.EndOfStream => return null,
            else => |e| return e,
        };
        const rex = parseRexPrefix(&self.stream) catch |err| switch (err) {
            error.EndOfStream => return null,
            else => |e| return e,
        };
        const reader = self.stream.reader();
        var opc = try ParsedOpc.parse(reader);
        const bit_size = opc.bitSize(rex, prefixes);

        const data: Instruction.Data = data: {
            switch (opc.enc) {
                .i => {
                    const imm = try parseImm(reader, bit_size);
                    break :data Instruction.Data.i(imm, bit_size);
                },
                .fd, .td => {
                    const imm = try reader.readInt(u64, .Little);
                    const reg: Register = blk: {
                        if (prefixes.prefix_2e) break :blk .cs;
                        if (prefixes.prefix_36) break :blk .ss;
                        if (prefixes.prefix_26) break :blk .es;
                        if (prefixes.prefix_64) break :blk .fs;
                        if (prefixes.prefix_65) break :blk .gs;
                        break :blk .ds;
                    };
                    const ptr_size: Memory.PtrSize = blk: {
                        if (bit_size <= 8) break :blk .byte;
                        if (bit_size <= 16) break :blk .word;
                        if (bit_size <= 32) break :blk .dword;
                        break :blk .qword;
                    };
                    break :data Instruction.Data.fd(reg, imm, ptr_size);
                },
                .oi => {
                    if (rex.r or rex.x) return error.InvalidRexForEncoding;
                    const reg = Register.gprFromLowEnc(opc.extra, rex.b, bit_size);
                    const imm: u64 = switch (bit_size) {
                        8 => @bitCast(u64, @intCast(i64, try reader.readInt(i8, .Little))),
                        16, 32 => @bitCast(u64, @intCast(i64, try reader.readInt(i32, .Little))),
                        64 => try reader.readInt(u64, .Little),
                        else => unreachable,
                    };
                    break :data Instruction.Data.oi(reg, imm);
                },
                .mi, .mi8 => {
                    const modrm_byte = try reader.readByte();
                    const mod: u2 = @truncate(u2, modrm_byte >> 6);
                    const op1: u3 = @truncate(u3, modrm_byte >> 3);
                    const op2: u3 = @truncate(u3, modrm_byte);

                    assert(opc.is_wip);
                    opc.tag = switch (opc.byte) {
                        0x80, 0x81, 0x83 => switch (op1) {
                            0 => Instruction.Tag.add,
                            1 => Instruction.Tag.@"or",
                            2 => Instruction.Tag.adc,
                            3 => Instruction.Tag.sbb,
                            4 => Instruction.Tag.@"and",
                            5 => Instruction.Tag.sub,
                            6 => Instruction.Tag.xor,
                            7 => Instruction.Tag.cmp,
                        },
                        0xc6, 0xc7 => switch (op1) {
                            0 => Instruction.Tag.mov,
                            else => unreachable, // unsupported MI encoding
                        },
                        else => unreachable, // unhandled MI encoding
                    };

                    const imm_bit_size = if (opc.enc == .mi8) 8 else bit_size;

                    switch (mod) {
                        0b11 => {
                            const reg = Register.gprFromLowEnc(op2, rex.b, bit_size);
                            const imm = try parseImm(reader, imm_bit_size);
                            break :data Instruction.Data.mi(RegisterOrMemory.reg(reg), imm);
                        },
                        0b01 => {
                            // indirect addressing with an 8bit displacement
                            if (op2 == 0b100) {
                                // TODO handle SIB byte addressing
                                return error.Todo;
                            }

                            const reg = Register.gprFromLowEnc(op2, rex.b, 64);
                            const disp = try reader.readInt(i8, .Little);
                            const imm = try parseImm(reader, imm_bit_size);
                            break :data Instruction.Data.mi(RegisterOrMemory.mem(.{
                                .ptr_size = Memory.PtrSize.fromBitSize(bit_size),
                                .base = .{ .reg = reg },
                                .disp = disp,
                            }), imm);
                        },
                        0b10 => {
                            // indirect addressing with a 32bit displacement
                            if (op2 == 0b100) {
                                // TODO handle SIB byte addressing
                                return error.Todo;
                            }

                            const reg = Register.gprFromLowEnc(op2, rex.b, 64);
                            const disp = try reader.readInt(i32, .Little);
                            const imm = try parseImm(reader, imm_bit_size);
                            break :data Instruction.Data.mi(RegisterOrMemory.mem(.{
                                .ptr_size = Memory.PtrSize.fromBitSize(bit_size),
                                .base = .{ .reg = reg },
                                .disp = disp,
                            }), imm);
                        },
                        0b00 => {
                            // indirect addressing
                            if (op2 == 0b101) {
                                // RIP with 32bit displacement
                                const disp = try reader.readInt(i32, .Little);
                                const imm = try parseImm(reader, imm_bit_size);
                                break :data Instruction.Data.mi(RegisterOrMemory.mem(.{
                                    .ptr_size = Memory.PtrSize.fromBitSize(bit_size),
                                    .base = .rip,
                                    .disp = disp,
                                }), imm);
                            }

                            if (op2 == 0b100) {
                                // TODO SIB with disp 0bit
                                return error.Todo;
                            }

                            const reg = Register.gprFromLowEnc(op2, rex.b, 64);
                            const imm = try parseImm(reader, imm_bit_size);
                            break :data Instruction.Data.mi(RegisterOrMemory.mem(.{
                                .ptr_size = Memory.PtrSize.fromBitSize(bit_size),
                                .base = .{ .reg = reg },
                            }), imm);
                        },
                    }
                },
                .rm => {
                    const modrm_byte = try reader.readByte();
                    const mod: u2 = @truncate(u2, modrm_byte >> 6);
                    const op1: u3 = @truncate(u3, modrm_byte >> 3);
                    const op2: u3 = @truncate(u3, modrm_byte);

                    switch (mod) {
                        0b11 => {
                            // direct addressing
                            const reg1 = Register.gprFromLowEnc(op1, rex.r, bit_size);
                            const reg2 = Register.gprFromLowEnc(op2, rex.b, bit_size);
                            break :data Instruction.Data.rm(reg1, RegisterOrMemory.reg(reg2));
                        },
                        0b01 => {
                            // indirect addressing with an 8bit displacement
                            if (op2 == 0b100) {
                                // TODO handle SIB byte addressing
                                return error.Todo;
                            }

                            const reg1 = Register.gprFromLowEnc(op1, rex.r, bit_size);
                            const reg2 = Register.gprFromLowEnc(op2, rex.b, 64);
                            const disp = try reader.readInt(i8, .Little);
                            break :data Instruction.Data.rm(reg1, RegisterOrMemory.mem(.{
                                .ptr_size = Memory.PtrSize.fromBitSize(bit_size),
                                .base = .{ .reg = reg2 },
                                .disp = disp,
                            }));
                        },
                        0b10 => {
                            // indirect addressing with a 32bit displacement
                            if (op2 == 0b100) {
                                // TODO handle SIB byte addressing
                                return error.Todo;
                            }

                            const reg1 = Register.gprFromLowEnc(op1, rex.r, bit_size);
                            const reg2 = Register.gprFromLowEnc(op2, rex.b, 64);
                            const disp = try reader.readInt(i32, .Little);
                            break :data Instruction.Data.rm(reg1, RegisterOrMemory.mem(.{
                                .ptr_size = Memory.PtrSize.fromBitSize(bit_size),
                                .base = .{ .reg = reg2 },
                                .disp = disp,
                            }));
                        },
                        0b00 => {
                            // indirect addressing
                            if (op2 == 0b101) {
                                // RIP with 32bit displacement
                                const reg1 = Register.gprFromLowEnc(op1, rex.r, bit_size);
                                const disp = try reader.readInt(i32, .Little);
                                break :data Instruction.Data.rm(reg1, RegisterOrMemory.mem(.{
                                    .ptr_size = Memory.PtrSize.fromBitSize(bit_size),
                                    .base = .rip,
                                    .disp = disp,
                                }));
                            }

                            if (op2 == 0b100) {
                                // TODO SIB with disp 0bit
                                return error.Todo;
                            }

                            const reg1 = Register.gprFromLowEnc(op1, rex.r, bit_size);
                            const reg2 = Register.gprFromLowEnc(op2, rex.b, 64);
                            break :data Instruction.Data.rm(reg1, RegisterOrMemory.mem(.{
                                .ptr_size = Memory.PtrSize.fromBitSize(bit_size),
                                .base = .{ .reg = reg2 },
                            }));
                        },
                    }
                },
                .mr => {
                    const modrm_byte = try reader.readByte();
                    const mod: u2 = @truncate(u2, modrm_byte >> 6);
                    const op2: u3 = @truncate(u3, modrm_byte >> 3);
                    const op1: u3 = @truncate(u3, modrm_byte);

                    switch (mod) {
                        0b11 => {
                            // direct addressing
                            const reg1 = Register.gprFromLowEnc(op1, rex.b, bit_size);
                            const reg2 = Register.gprFromLowEnc(op2, rex.r, bit_size);
                            break :data Instruction.Data.mr(RegisterOrMemory.reg(reg1), reg2);
                        },
                        0b01 => {
                            // indirect addressing with an 8bit displacement
                            if (op2 == 0b100) {
                                // TODO handle SIB byte addressing
                                return error.Todo;
                            }

                            const reg1 = Register.gprFromLowEnc(op1, rex.b, 64);
                            const reg2 = Register.gprFromLowEnc(op2, rex.r, bit_size);
                            const disp = try reader.readInt(i8, .Little);
                            break :data Instruction.Data.mr(RegisterOrMemory.mem(.{
                                .ptr_size = Memory.PtrSize.fromBitSize(bit_size),
                                .base = .{ .reg = reg1 },
                                .disp = disp,
                            }), reg2);
                        },
                        0b10 => {
                            // indirect addressing with a 32bit displacement
                            if (op2 == 0b100) {
                                // TODO handle SIB byte addressing
                                return error.Todo;
                            }

                            const reg1 = Register.gprFromLowEnc(op1, rex.b, 64);
                            const reg2 = Register.gprFromLowEnc(op2, rex.r, bit_size);
                            const disp = try reader.readInt(i32, .Little);
                            break :data Instruction.Data.mr(RegisterOrMemory.mem(.{
                                .ptr_size = Memory.PtrSize.fromBitSize(bit_size),
                                .base = .{ .reg = reg1 },
                                .disp = disp,
                            }), reg2);
                        },
                        0b00 => {
                            // indirect addressing
                            if (op2 == 0b101) {
                                // RIP with 32bit displacement
                                const reg1 = Register.gprFromLowEnc(op1, rex.b, bit_size);
                                const disp = try reader.readInt(i32, .Little);
                                break :data Instruction.Data.mr(RegisterOrMemory.mem(.{
                                    .ptr_size = Memory.PtrSize.fromBitSize(bit_size),
                                    .base = .rip,
                                    .disp = disp,
                                }), reg1);
                            }

                            if (op2 == 0b100) {
                                // TODO SIB with disp 0bit
                                return error.Todo;
                            }

                            const reg1 = Register.gprFromLowEnc(op1, rex.b, 64);
                            const reg2 = Register.gprFromLowEnc(op2, rex.r, bit_size);
                            break :data Instruction.Data.mr(RegisterOrMemory.mem(.{
                                .ptr_size = Memory.PtrSize.fromBitSize(bit_size),
                                .base = .{ .reg = reg1 },
                            }), reg2);
                        },
                    }
                },
            }
        };

        return Instruction{
            .tag = opc.tag,
            .enc = opc.enc,
            .data = data,
        };
    }
};

const ParsedOpc = struct {
    tag: Instruction.Tag,
    enc: Instruction.Enc,
    is_byte_sized: bool,
    extra: u3,
    /// Set to false once we know exactly what instruction we are dealing with.
    is_wip: bool,
    byte: u8,

    fn parse(reader: anytype) Error!ParsedOpc {
        const next_byte = try reader.readByte();
        var opc: ParsedOpc = blk: {
            switch (next_byte) {
                // MI encoding will be resolved fully later, once
                // we parse the ModRM byte.
                0x80 => break :blk ParsedOpc.wip(.mi, true),
                0x81 => break :blk ParsedOpc.wip(.mi, false),
                0x83 => break :blk ParsedOpc.wip(.mi8, false),
                0xc6 => break :blk ParsedOpc.wip(.mi, true),
                0xc7 => break :blk ParsedOpc.wip(.mi, false),
                // adc
                0x14 => break :blk ParsedOpc.new(.adc, .i, true),
                0x15 => break :blk ParsedOpc.new(.adc, .i, false),
                0x10 => break :blk ParsedOpc.new(.adc, .mr, true),
                0x11 => break :blk ParsedOpc.new(.adc, .mr, false),
                0x12 => break :blk ParsedOpc.new(.adc, .rm, true),
                0x13 => break :blk ParsedOpc.new(.adc, .rm, false),
                // add
                0x04 => break :blk ParsedOpc.new(.add, .i, true),
                0x05 => break :blk ParsedOpc.new(.add, .i, false),
                0x00 => break :blk ParsedOpc.new(.add, .mr, true),
                0x01 => break :blk ParsedOpc.new(.add, .mr, false),
                0x02 => break :blk ParsedOpc.new(.add, .rm, true),
                0x03 => break :blk ParsedOpc.new(.add, .rm, false),
                // and
                0x24 => break :blk ParsedOpc.new(.@"and", .i, true),
                0x25 => break :blk ParsedOpc.new(.@"and", .i, false),
                0x20 => break :blk ParsedOpc.new(.@"and", .mr, true),
                0x21 => break :blk ParsedOpc.new(.@"and", .mr, false),
                0x22 => break :blk ParsedOpc.new(.@"and", .rm, true),
                0x23 => break :blk ParsedOpc.new(.@"and", .rm, false),
                // cmp
                0x3c => break :blk ParsedOpc.new(.cmp, .i, true),
                0x3d => break :blk ParsedOpc.new(.cmp, .i, false),
                0x38 => break :blk ParsedOpc.new(.cmp, .mr, true),
                0x39 => break :blk ParsedOpc.new(.cmp, .mr, false),
                0x3a => break :blk ParsedOpc.new(.cmp, .rm, true),
                0x3b => break :blk ParsedOpc.new(.cmp, .rm, false),
                // mov
                0x88 => break :blk ParsedOpc.new(.mov, .mr, true),
                0x89 => break :blk ParsedOpc.new(.mov, .mr, false),
                0x8a => break :blk ParsedOpc.new(.mov, .rm, true),
                0x8b => break :blk ParsedOpc.new(.mov, .rm, false),
                0x8c => break :blk ParsedOpc.new(.mov, .mr, false),
                0x8e => break :blk ParsedOpc.new(.mov, .rm, false),
                0xa0 => break :blk ParsedOpc.new(.mov, .fd, true),
                0xa1 => break :blk ParsedOpc.new(.mov, .fd, false),
                0xa2 => break :blk ParsedOpc.new(.mov, .td, true),
                0xa3 => break :blk ParsedOpc.new(.mov, .td, false),
                // or
                0x0c => break :blk ParsedOpc.new(.@"or", .i, true),
                0x0d => break :blk ParsedOpc.new(.@"or", .i, false),
                0x08 => break :blk ParsedOpc.new(.@"or", .mr, true),
                0x09 => break :blk ParsedOpc.new(.@"or", .mr, false),
                0x0a => break :blk ParsedOpc.new(.@"or", .rm, true),
                0x0b => break :blk ParsedOpc.new(.@"or", .rm, false),
                // sbb
                0x1c => break :blk ParsedOpc.new(.sbb, .i, true),
                0x1d => break :blk ParsedOpc.new(.sbb, .i, false),
                0x18 => break :blk ParsedOpc.new(.sbb, .mr, true),
                0x19 => break :blk ParsedOpc.new(.sbb, .mr, false),
                0x1a => break :blk ParsedOpc.new(.sbb, .rm, true),
                0x1b => break :blk ParsedOpc.new(.sbb, .rm, false),
                // sub
                0x2c => break :blk ParsedOpc.new(.sub, .i, true),
                0x2d => break :blk ParsedOpc.new(.sub, .i, false),
                0x28 => break :blk ParsedOpc.new(.sub, .mr, true),
                0x29 => break :blk ParsedOpc.new(.sub, .mr, false),
                0x2a => break :blk ParsedOpc.new(.sub, .rm, true),
                0x2b => break :blk ParsedOpc.new(.sub, .rm, false),
                // xor
                0x34 => break :blk ParsedOpc.new(.xor, .i, true),
                0x35 => break :blk ParsedOpc.new(.xor, .i, false),
                0x30 => break :blk ParsedOpc.new(.xor, .mr, true),
                0x31 => break :blk ParsedOpc.new(.xor, .mr, false),
                0x32 => break :blk ParsedOpc.new(.xor, .rm, true),
                0x33 => break :blk ParsedOpc.new(.xor, .rm, false),
                // lea
                0x8d => break :blk ParsedOpc.new(.lea, .rm, false),
                // remaining
                else => {},
            }

            // check for OI encoding
            const mask: u8 = 0b1111_1000;
            switch (next_byte & mask) {
                // mov
                0xb0 => break :blk ParsedOpc.newWithExtra(.mov, .oi, true, @truncate(u3, next_byte)),
                0xb8 => break :blk ParsedOpc.newWithExtra(.mov, .oi, false, @truncate(u3, next_byte)),
                // remaining
                else => return error.Todo,
            }
        };
        opc.byte = next_byte;
        return opc;
    }

    fn new(tag: Instruction.Tag, enc: Instruction.Enc, is_byte_sized: bool) ParsedOpc {
        return .{
            .tag = tag,
            .enc = enc,
            .is_byte_sized = is_byte_sized,
            .extra = undefined,
            .is_wip = false,
            .byte = undefined,
        };
    }

    fn newWithExtra(tag: Instruction.Tag, enc: Instruction.Enc, is_byte_sized: bool, extra: u3) ParsedOpc {
        return .{
            .tag = tag,
            .enc = enc,
            .is_byte_sized = is_byte_sized,
            .extra = extra,
            .is_wip = false,
            .byte = undefined,
        };
    }

    fn wip(enc: Instruction.Enc, is_byte_sized: bool) ParsedOpc {
        return .{
            .tag = undefined,
            .enc = enc,
            .is_byte_sized = is_byte_sized,
            .extra = undefined,
            .is_wip = true,
            .byte = undefined,
        };
    }

    fn bitSize(self: ParsedOpc, rex: Rex, prefixes: LegacyPrefixes) u7 {
        if (self.is_byte_sized) return 8;
        if (rex.w) return 64;
        if (prefixes.prefix_66) return 16;
        return 32;
    }
};

fn parseImm(reader: anytype, bit_size: u7) !i32 {
    const imm: i32 = switch (bit_size) {
        8 => try reader.readInt(i8, .Little),
        16 => try reader.readInt(i16, .Little),
        32, 64 => try reader.readInt(i32, .Little),
        else => unreachable,
    };
    return imm;
}

fn parseLegacyPrefixes(stream: anytype) !LegacyPrefixes {
    var out = LegacyPrefixes{};
    while (true) {
        const next_byte = try stream.reader().readByte();
        switch (next_byte) {
            0xf0 => out.prefix_f0 = true,
            0xf2 => out.prefix_f2 = true,
            0xf3 => out.prefix_f3 = true,

            0x2e => out.prefix_2e = true,
            0x36 => out.prefix_36 = true,
            0x26 => out.prefix_26 = true,
            0x64 => out.prefix_64 = true,
            0x65 => out.prefix_65 = true,

            0x3e => out.prefix_3e = true,

            0x66 => out.prefix_66 = true,

            0x67 => out.prefix_67 = true,

            else => {
                try stream.seekBy(-1);
                break;
            },
        }
    }
    return out;
}

fn parseRexPrefix(stream: anytype) !Rex {
    const next_byte = try stream.reader().readByte();
    const rex: Rex = Rex.parse(next_byte) orelse blk: {
        try stream.seekBy(-1);
        break :blk .{};
    };
    return rex;
}
