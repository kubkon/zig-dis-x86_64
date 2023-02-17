const std = @import("std");
const assert = std.debug.assert;
const math = std.math;

const bits = @import("bits.zig");
const encoder = @import("encoder.zig");

const Instruction = encoder.Instruction;
const LegacyPrefixes = encoder.LegacyPrefixes;
const Memory = bits.Memory;
const PtrSize = bits.PtrSize;
const Register = bits.Register;
const RegisterOrMemory = bits.RegisterOrMemory;
const Rex = encoder.Rex;
const ScaleIndex = bits.ScaleIndex;

const Allocator = std.mem.Allocator;

pub const Error = error{
    EndOfStream,
    InvalidModRmByte,
    InvalidRexForEncoding,
    Todo,
};

pub const Disassembler = struct {
    code: []const u8,
    pos: usize = 0,

    pub fn init(code: []const u8) Disassembler {
        return .{ .code = code };
    }

    pub fn next(self: *Disassembler) Error!?Instruction {
        const prefixes = self.parseLegacyPrefixes() catch |err| switch (err) {
            error.EndOfStream => return null,
            else => |e| return e,
        };
        const rex = self.parseRexPrefix() catch |err| switch (err) {
            error.EndOfStream => return null,
            else => |e| return e,
        };

        var stream = std.io.fixedBufferStream(self.code[self.pos..]);
        var creader = std.io.countingReader(stream.reader());
        const reader = creader.reader();

        var opc = try ParsedOpc.parse(reader);
        const bit_size = opc.bitSize(rex, prefixes);

        const data: Instruction.Data = data: {
            switch (opc.enc) {
                .np => break :data Instruction.Data.np(),

                .o => {
                    const reg = Register.gpFromLowEnc(opc.extra, rex.b, bit_size);
                    break :data Instruction.Data.o(reg);
                },

                .i => {
                    const imm = try parseImm(bit_size, reader);
                    break :data Instruction.Data.i(imm, bit_size);
                },

                .m_rel => {
                    const imm = try parseImm(32, reader);
                    break :data Instruction.Data.mRel(imm);
                },

                .m => {
                    const modrm = try parseModRmByte(reader);
                    const sib = try parseSibByte(modrm, reader);
                    const disp = try parseDisplacement(modrm, sib, reader);

                    assert(opc.is_wip);
                    assert(opc.opc_byte_count == 1);
                    opc.tag = switch (opc.bytes[0]) {
                        0xff => switch (modrm.op1) {
                            2 => Instruction.Tag.call,
                            else => unreachable, // TODO
                        },
                        else => unreachable, // unhandled M encoding
                    };

                    if (modrm.isRip()) {
                        break :data Instruction.Data.m(RegisterOrMemory.rip(PtrSize.fromBitSize(bit_size), disp));
                    }

                    if (modrm.isDirect()) {
                        const reg = Register.gpFromLowEnc(modrm.op2, rex.b, bit_size);
                        break :data Instruction.Data.m(RegisterOrMemory.reg(reg));
                    }

                    const scale_index: ?ScaleIndex = if (sib) |info| info.scaleIndex(rex) else null;
                    const base: ?Register = if (sib) |info|
                        info.baseReg(modrm, rex, prefixes)
                    else
                        Register.gpFromLowEnc(modrm.op2, rex.b, 64);
                    break :data Instruction.Data.m(RegisterOrMemory.mem(PtrSize.fromBitSize(bit_size), .{
                        .scale_index = scale_index,
                        .base = base,
                        .disp = disp,
                    }));
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
                    const ptr_size: PtrSize = blk: {
                        if (bit_size <= 8) break :blk .byte;
                        if (bit_size <= 16) break :blk .word;
                        if (bit_size <= 32) break :blk .dword;
                        break :blk .qword;
                    };
                    break :data Instruction.Data.fd(reg, imm, ptr_size);
                },

                .oi => {
                    if (rex.r or rex.x) return error.InvalidRexForEncoding;
                    const reg = Register.gpFromLowEnc(opc.extra, rex.b, bit_size);
                    const imm: u64 = switch (bit_size) {
                        8 => @bitCast(u64, @intCast(i64, try reader.readInt(i8, .Little))),
                        16, 32 => @bitCast(u64, @intCast(i64, try reader.readInt(i32, .Little))),
                        64 => try reader.readInt(u64, .Little),
                        else => unreachable,
                    };
                    break :data Instruction.Data.oi(reg, imm);
                },

                .mi, .mi8 => {
                    const modrm = try parseModRmByte(reader);
                    const sib = try parseSibByte(modrm, reader);
                    const disp = try parseDisplacement(modrm, sib, reader);

                    assert(opc.is_wip);
                    assert(opc.opc_byte_count == 1);
                    opc.tag = switch (opc.bytes[0]) {
                        0x80, 0x81, 0x83 => switch (modrm.op1) {
                            0 => Instruction.Tag.add,
                            1 => Instruction.Tag.@"or",
                            2 => Instruction.Tag.adc,
                            3 => Instruction.Tag.sbb,
                            4 => Instruction.Tag.@"and",
                            5 => Instruction.Tag.sub,
                            6 => Instruction.Tag.xor,
                            7 => Instruction.Tag.cmp,
                        },
                        0xc6, 0xc7 => switch (modrm.op1) {
                            0 => Instruction.Tag.mov,
                            else => unreachable, // unsupported MI encoding
                        },
                        else => unreachable, // unhandled MI encoding
                    };

                    const imm_bit_size = if (opc.enc == .mi8) 8 else bit_size;
                    const imm = try parseImm(imm_bit_size, reader);

                    if (modrm.isRip()) {
                        break :data Instruction.Data.mi(RegisterOrMemory.rip(PtrSize.fromBitSize(bit_size), disp), imm);
                    }

                    if (modrm.isDirect()) {
                        const reg = Register.gpFromLowEnc(modrm.op2, rex.b, bit_size);
                        break :data Instruction.Data.mi(RegisterOrMemory.reg(reg), imm);
                    }

                    const scale_index: ?ScaleIndex = if (sib) |info| info.scaleIndex(rex) else null;
                    const base: ?Register = if (sib) |info|
                        info.baseReg(modrm, rex, prefixes)
                    else
                        Register.gpFromLowEnc(modrm.op2, rex.b, 64);
                    break :data Instruction.Data.mi(RegisterOrMemory.mem(PtrSize.fromBitSize(bit_size), .{
                        .scale_index = scale_index,
                        .base = base,
                        .disp = disp,
                    }), imm);
                },

                .rm => {
                    const modrm = try parseModRmByte(reader);
                    const sib = try parseSibByte(modrm, reader);
                    const disp = try parseDisplacement(modrm, sib, reader);

                    const dst_bit_size = bit_size;
                    const src_bit_size = bit_size;

                    if (modrm.isRip()) {
                        const reg1 = Register.gpFromLowEnc(modrm.op1, rex.r, dst_bit_size);
                        break :data Instruction.Data.rm(reg1, RegisterOrMemory.rip(PtrSize.fromBitSize(src_bit_size), disp));
                    }

                    if (modrm.isDirect()) {
                        const reg1 = Register.gpFromLowEnc(modrm.op1, rex.r, dst_bit_size);
                        const reg2 = Register.gpFromLowEnc(modrm.op2, rex.b, src_bit_size);
                        break :data Instruction.Data.rm(reg1, RegisterOrMemory.reg(reg2));
                    }

                    const reg = Register.gpFromLowEnc(modrm.op1, rex.r, dst_bit_size);
                    const scale_index: ?ScaleIndex = if (sib) |info| info.scaleIndex(rex) else null;
                    const base: ?Register = if (sib) |info|
                        info.baseReg(modrm, rex, prefixes)
                    else
                        Register.gpFromLowEnc(modrm.op2, rex.b, 64);
                    break :data Instruction.Data.rm(reg, RegisterOrMemory.mem(PtrSize.fromBitSize(src_bit_size), .{
                        .scale_index = scale_index,
                        .base = base,
                        .disp = disp,
                    }));
                },

                .mr => {
                    const modrm = try parseModRmByte(reader);
                    const sib = try parseSibByte(modrm, reader);
                    const disp = try parseDisplacement(modrm, sib, reader);

                    if (modrm.isRip()) {
                        const reg = Register.gpFromLowEnc(modrm.op1, rex.r, bit_size);
                        break :data Instruction.Data.mr(RegisterOrMemory.rip(PtrSize.fromBitSize(bit_size), disp), reg);
                    }

                    if (modrm.isDirect()) {
                        const reg1 = Register.gpFromLowEnc(modrm.op2, rex.b, bit_size);
                        const reg2 = Register.gpFromLowEnc(modrm.op1, rex.r, bit_size);
                        break :data Instruction.Data.mr(RegisterOrMemory.reg(reg1), reg2);
                    }

                    const scale_index: ?ScaleIndex = if (sib) |info| info.scaleIndex(rex) else null;
                    const base: ?Register = if (sib) |info|
                        info.baseReg(modrm, rex, prefixes)
                    else
                        Register.gpFromLowEnc(modrm.op2, rex.b, 64);
                    const reg = Register.gpFromLowEnc(modrm.op1, rex.r, bit_size);
                    break :data Instruction.Data.mr(RegisterOrMemory.mem(PtrSize.fromBitSize(bit_size), .{
                        .scale_index = scale_index,
                        .base = base,
                        .disp = disp,
                    }), reg);
                },
            }
        };

        self.pos += creader.bytes_read;

        return Instruction{
            .tag = opc.tag,
            .enc = opc.enc,
            .data = data,
        };
    }

    fn parseImm(bit_size: u64, reader: anytype) !i32 {
        const imm: i32 = switch (bit_size) {
            8 => try reader.readInt(i8, .Little),
            16 => try reader.readInt(i16, .Little),
            32, 64 => try reader.readInt(i32, .Little),
            else => unreachable,
        };
        return imm;
    }

    fn parseLegacyPrefixes(self: *Disassembler) !LegacyPrefixes {
        var stream = std.io.fixedBufferStream(self.code[self.pos..]);
        const reader = stream.reader();
        var out = LegacyPrefixes{};
        while (true) {
            const next_byte = try reader.readByte();
            self.pos += 1;

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
                    self.pos -= 1;
                    break;
                },
            }
        }
        return out;
    }

    fn parseRexPrefix(self: *Disassembler) !Rex {
        var stream = std.io.fixedBufferStream(self.code[self.pos..]);
        const reader = stream.reader();
        const next_byte = try reader.readByte();
        self.pos += 1;
        const rex: Rex = Rex.parse(next_byte) orelse blk: {
            self.pos -= 1;
            break :blk .{};
        };
        return rex;
    }
};

const ParsedOpc = struct {
    tag: Instruction.Tag,
    enc: Instruction.Enc,
    is_byte_sized: bool,
    extra: u3,
    /// Set to false once we know exactly what instruction we are dealing with.
    is_wip: bool,
    /// Set to true if the instruction is defined by a multibyte opcode.
    is_multi_byte: bool,
    bytes: [3]u8 = undefined,
    opc_byte_count: u2 = 0,

    fn parse(reader: anytype) Error!ParsedOpc {
        const next_byte = try reader.readByte();
        var opc: ParsedOpc = blk: {
            switch (next_byte) {
                // M and MI encodings will be resolved fully later, once
                // we parse the ModRM byte.
                0x80 => break :blk ParsedOpc.wip(.mi, true),
                0x81 => break :blk ParsedOpc.wip(.mi, false),
                0x83 => break :blk ParsedOpc.wip(.mi8, false),
                0xc6 => break :blk ParsedOpc.wip(.mi, true),
                0xc7 => break :blk ParsedOpc.wip(.mi, false),
                0xff => break :blk ParsedOpc.wip(.m, false),
                // Multi-byte opcodes will be resolved fully later, once
                // we parse additional bytes
                0x0f => break :blk ParsedOpc.multiByte(),
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
                // call
                0xe8 => break :blk ParsedOpc.new(.call, .m_rel, false),
                // cmp
                0x3c => break :blk ParsedOpc.new(.cmp, .i, true),
                0x3d => break :blk ParsedOpc.new(.cmp, .i, false),
                0x38 => break :blk ParsedOpc.new(.cmp, .mr, true),
                0x39 => break :blk ParsedOpc.new(.cmp, .mr, false),
                0x3a => break :blk ParsedOpc.new(.cmp, .rm, true),
                0x3b => break :blk ParsedOpc.new(.cmp, .rm, false),
                // int3
                0xcc => break :blk ParsedOpc.new(.int3, .np, false),
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
                // movsxd
                0x63 => break :blk ParsedOpc.new(.movsxd, .rm, false),
                // or
                0x0c => break :blk ParsedOpc.new(.@"or", .i, true),
                0x0d => break :blk ParsedOpc.new(.@"or", .i, false),
                0x08 => break :blk ParsedOpc.new(.@"or", .mr, true),
                0x09 => break :blk ParsedOpc.new(.@"or", .mr, false),
                0x0a => break :blk ParsedOpc.new(.@"or", .rm, true),
                0x0b => break :blk ParsedOpc.new(.@"or", .rm, false),
                // push
                0x6a => break :blk ParsedOpc.new(.push, .i, true),
                0x68 => break :blk ParsedOpc.new(.push, .i, false),
                // ret
                0xc3 => break :blk ParsedOpc.new(.ret, .np, false),
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

            // check for O/OI encoding
            const mask: u8 = 0b1111_1000;
            switch (next_byte & mask) {
                // mov
                0x50 => break :blk ParsedOpc.newWithExtra(.push, .o, false, @truncate(u3, next_byte)),
                0x58 => break :blk ParsedOpc.newWithExtra(.pop, .o, false, @truncate(u3, next_byte)),
                0xb0 => break :blk ParsedOpc.newWithExtra(.mov, .oi, true, @truncate(u3, next_byte)),
                0xb8 => break :blk ParsedOpc.newWithExtra(.mov, .oi, false, @truncate(u3, next_byte)),
                // remaining
                else => return error.Todo,
            }
        };
        opc.bytes[0] = next_byte;
        opc.opc_byte_count = 1;

        if (opc.is_multi_byte) {
            try opc.resolveMultiByte(reader);
        }

        return opc;
    }

    fn resolveMultiByte(opc: *ParsedOpc, reader: anytype) !void {
        assert(opc.is_wip);
        var count: u2 = 0;
        while (count < 2) : (count += 1) {
            const next_next_byte = try reader.readByte();
            opc.bytes[count + 1] = next_next_byte;
            opc.opc_byte_count += 1;

            switch (next_next_byte) {
                0x05 => {
                    opc.tag = .syscall;
                    opc.enc = .np;
                    break;
                },

                0xbe, 0xbf => {
                    opc.tag = .movsx;
                    opc.is_byte_sized = next_next_byte == 0xbe;
                    opc.enc = .rm;
                    break;
                },

                else => return error.Todo,
            }
        }
        opc.is_wip = false;
    }

    fn new(tag: Instruction.Tag, enc: Instruction.Enc, is_byte_sized: bool) ParsedOpc {
        return .{
            .tag = tag,
            .enc = enc,
            .is_byte_sized = is_byte_sized,
            .extra = undefined,
            .is_wip = false,
            .is_multi_byte = false,
        };
    }

    fn newWithExtra(tag: Instruction.Tag, enc: Instruction.Enc, is_byte_sized: bool, extra: u3) ParsedOpc {
        return .{
            .tag = tag,
            .enc = enc,
            .is_byte_sized = is_byte_sized,
            .extra = extra,
            .is_wip = false,
            .is_multi_byte = false,
        };
    }

    fn wip(enc: Instruction.Enc, is_byte_sized: bool) ParsedOpc {
        return .{
            .tag = undefined,
            .enc = enc,
            .is_byte_sized = is_byte_sized,
            .extra = undefined,
            .is_wip = true,
            .is_multi_byte = false,
        };
    }

    fn multiByte() ParsedOpc {
        return .{
            .tag = undefined,
            .enc = undefined,
            .is_byte_sized = false,
            .extra = undefined,
            .is_wip = true,
            .is_multi_byte = true,
        };
    }

    fn bitSize(self: ParsedOpc, rex: Rex, prefixes: LegacyPrefixes) u64 {
        if (self.is_byte_sized) return 8;
        if (rex.w) return 64;
        if (prefixes.prefix_66) return 16;
        switch (self.enc) {
            .o, .m => return 64,
            else => return 32,
        }
    }
};

const ModRm = packed struct {
    mod: u2,
    op1: u3,
    op2: u3,

    inline fn isDirect(self: ModRm) bool {
        return self.mod == 0b11;
    }

    inline fn isRip(self: ModRm) bool {
        return self.mod == 0 and self.op2 == 0b101;
    }

    inline fn usesSib(self: ModRm) bool {
        return !self.isDirect() and self.op2 == 0b100;
    }
};

fn parseModRmByte(reader: anytype) !ModRm {
    const modrm_byte = try reader.readByte();
    const mod: u2 = @truncate(u2, modrm_byte >> 6);
    const op1: u3 = @truncate(u3, modrm_byte >> 3);
    const op2: u3 = @truncate(u3, modrm_byte);
    return ModRm{ .mod = mod, .op1 = op1, .op2 = op2 };
}

const Sib = packed struct {
    ss: u2,
    index: u3,
    base: u3,

    fn scaleIndex(self: Sib, rex: Rex) ?ScaleIndex {
        if (self.index == 0b100 and !rex.x) return null;
        return ScaleIndex{
            .scale = self.ss,
            .index = Register.gpFromLowEnc(self.index, rex.x, 64),
        };
    }

    fn baseReg(self: Sib, modrm: ModRm, rex: Rex, prefixes: LegacyPrefixes) ?Register {
        if (self.base == 0b101 and modrm.mod == 0) {
            if (self.scaleIndex(rex)) |_| return null;
            // Segment register
            if (prefixes.prefix_2e) return .cs;
            if (prefixes.prefix_36) return .ss;
            if (prefixes.prefix_26) return .es;
            if (prefixes.prefix_64) return .fs;
            if (prefixes.prefix_65) return .gs;
            return .ds;
        }
        return Register.gpFromLowEnc(self.base, rex.b, 64);
    }
};

fn parseSibByte(modrm: ModRm, reader: anytype) !?Sib {
    if (!modrm.usesSib()) return null;
    const sib_byte = try reader.readByte();
    const ss: u2 = @truncate(u2, sib_byte >> 6);
    const index: u3 = @truncate(u3, sib_byte >> 3);
    const base: u3 = @truncate(u3, sib_byte);
    return Sib{ .ss = ss, .index = index, .base = base };
}

fn parseDisplacement(modrm: ModRm, sib: ?Sib, reader: anytype) !i32 {
    if (sib) |info| {
        if (info.base == 0b101 and modrm.mod == 0) {
            return try reader.readInt(i32, .Little);
        }
    }
    if (modrm.isRip()) {
        return try reader.readInt(i32, .Little);
    }
    return switch (modrm.mod) {
        0b01 => try reader.readInt(i8, .Little),
        0b10 => try reader.readInt(i32, .Little),
        else => 0,
    };
}
