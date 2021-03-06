const std = @import("std");
const assert = std.debug.assert;
const math = std.math;

const bits = @import("bits.zig");
const encoder = @import("encoder.zig");

const Instruction = encoder.Instruction;
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
        const reader = self.stream.reader();

        const next_byte = reader.readByte() catch |err| switch (err) {
            error.EndOfStream => return null,
            else => |e| return e,
        };

        // TODO parse legacy prefixes such as 0x66, etc.
        const rex: Rex = Rex.parse(next_byte) orelse blk: {
            try self.stream.seekBy(-1);
            break :blk .{};
        };
        var opc = try ParsedOpc.parse(reader);
        const bit_size = opc.bitSize(rex);

        const data: Instruction.Data = data: {
            switch (opc.enc) {
                .oi => {
                    if (rex.r or rex.x) return error.InvalidRexForEncoding;
                    const reg = Register.fromLowEnc(opc.extra, rex.b, bit_size);
                    const imm: u64 = switch (bit_size) {
                        8 => @bitCast(u64, @intCast(i64, try reader.readInt(i8, .Little))),
                        16, 32 => @bitCast(u64, @intCast(i64, try reader.readInt(i32, .Little))),
                        64 => try reader.readInt(u64, .Little),
                        else => unreachable,
                    };
                    break :data Instruction.Data.oi(reg, imm);
                },
                .mi => {
                    const modrm_byte = try reader.readByte();
                    const mod: u2 = @truncate(u2, modrm_byte >> 6);
                    const op1: u3 = @truncate(u3, modrm_byte >> 3);
                    const op2: u3 = @truncate(u3, modrm_byte);

                    assert(opc.is_wip);
                    opc.tag = switch (op1) {
                        0 => switch (opc.byte) {
                            0x80, 0x81 => Instruction.Tag.add,
                            0xc6, 0xc7 => Instruction.Tag.mov,
                            else => unreachable,
                        },
                        7 => switch (opc.byte) {
                            0x80, 0x81 => Instruction.Tag.cmp,
                            else => unreachable,
                        },
                        else => unreachable,
                    };

                    switch (mod) {
                        0b11 => {
                            const reg = Register.fromLowEnc(op2, rex.r, bit_size);
                            const imm = try parseImm(reader, bit_size);
                            break :data Instruction.Data.mi(RegisterOrMemory.reg(reg), imm);
                        },
                        0b01 => {
                            // indirect addressing with an 8bit displacement
                            if (op2 == 0b100) {
                                // TODO handle SIB byte addressing
                                return error.Todo;
                            }

                            const reg = Register.fromLowEnc(op2, rex.b, 64);
                            const disp = try reader.readInt(i8, .Little);
                            const imm = try parseImm(reader, bit_size);
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

                            const reg = Register.fromLowEnc(op2, rex.b, 64);
                            const disp = try reader.readInt(i32, .Little);
                            const imm = try parseImm(reader, bit_size);
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
                                const imm = try parseImm(reader, bit_size);
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

                            const reg = Register.fromLowEnc(op2, rex.b, 64);
                            const imm = try parseImm(reader, bit_size);
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
                            const reg1 = Register.fromLowEnc(op1, rex.r, bit_size);
                            const reg2 = Register.fromLowEnc(op2, rex.b, bit_size);
                            break :data Instruction.Data.rm(reg1, RegisterOrMemory.reg(reg2));
                        },
                        0b01 => {
                            // indirect addressing with an 8bit displacement
                            if (op2 == 0b100) {
                                // TODO handle SIB byte addressing
                                return error.Todo;
                            }

                            const reg1 = Register.fromLowEnc(op1, rex.r, bit_size);
                            const reg2 = Register.fromLowEnc(op2, rex.b, 64);
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

                            const reg1 = Register.fromLowEnc(op1, rex.r, bit_size);
                            const reg2 = Register.fromLowEnc(op2, rex.b, 64);
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
                                const reg1 = Register.fromLowEnc(op1, rex.r, bit_size);
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

                            const reg1 = Register.fromLowEnc(op1, rex.r, bit_size);
                            const reg2 = Register.fromLowEnc(op2, rex.b, 64);
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
                            const reg1 = Register.fromLowEnc(op1, rex.b, bit_size);
                            const reg2 = Register.fromLowEnc(op2, rex.r, bit_size);
                            break :data Instruction.Data.mr(RegisterOrMemory.reg(reg1), reg2);
                        },
                        0b01 => {
                            // indirect addressing with an 8bit displacement
                            if (op2 == 0b100) {
                                // TODO handle SIB byte addressing
                                return error.Todo;
                            }

                            const reg1 = Register.fromLowEnc(op1, rex.b, 64);
                            const reg2 = Register.fromLowEnc(op2, rex.r, bit_size);
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

                            const reg1 = Register.fromLowEnc(op1, rex.b, 64);
                            const reg2 = Register.fromLowEnc(op2, rex.r, bit_size);
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
                                const reg1 = Register.fromLowEnc(op1, rex.b, bit_size);
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

                            const reg1 = Register.fromLowEnc(op1, rex.b, 64);
                            const reg2 = Register.fromLowEnc(op2, rex.r, bit_size);
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
                0xc6 => break :blk ParsedOpc.wip(.mi, true),
                0xc7 => break :blk ParsedOpc.wip(.mi, false),
                // add
                0x00 => break :blk ParsedOpc.new(.add, .mr, true),
                0x01 => break :blk ParsedOpc.new(.add, .mr, false),
                0x02 => break :blk ParsedOpc.new(.add, .rm, true),
                0x03 => break :blk ParsedOpc.new(.add, .rm, false),
                // cmp
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
                0xa0 => return error.Todo,
                0xa1 => return error.Todo,
                0xa2 => return error.Todo,
                0xa3 => return error.Todo,
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

    fn bitSize(self: ParsedOpc, rex: Rex) u7 {
        if (self.is_byte_sized) return 8;
        if (rex.w) return 64;
        // TODO handle legacy prefixes such as 0x66.
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
