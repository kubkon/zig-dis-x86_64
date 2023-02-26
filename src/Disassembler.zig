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
const PtrSize = bits.PtrSize;
const Register = bits.Register;
const Rex = encoder.Rex;
const ScaleIndex = bits.ScaleIndex;

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
    std.log.warn("{}", .{encoding});
    switch (encoding.op_en) {
        .oi, .zi => {
            const imm = try dis.parseImm(encoding.op2);
            return Instruction{
                .op1 = .{ .reg = Register.rax.toBitSize(encoding.op1.bitSize()) },
                .op2 = .{ .imm = imm },
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
                opcode[0] = opcode[0] & o_mask;
                return Encoding.findByOpcode(opcode[0..1], .{
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

const ParsedOpc = struct {
    tag: Instruction.Tag,
    enc: Instruction.Enc,
    extra: u3,
    /// Set to false once we know exactly what instruction we are dealing with.
    is_wip: bool,
    /// Set to true if the instruction is defined by a multibyte opcode.
    is_multi_byte: bool,
    bytes: [3]u8 = undefined,
    opc_byte_count: u2 = 0,

    const o_mask: u8 = 0b1111_1000;

    fn isDstByteSized(opc: ParsedOpc) bool {
        if (opc.is_multi_byte) return false; // TODO finish this
        switch (opc.enc) {
            .o => return false,
            .oi => return switch (opc.bytes[0] & o_mask) {
                0xb0 => true,
                else => false,
            },
            else => return switch (opc.bytes[0]) {
                // zig fmt: off
                0x00, 0x02, 0x04, // add
                0x08, 0x0a, 0x0c, // or
                0x10, 0x12, 0x14, // adc
                0x18, 0x1a, 0x1c, // sbb
                0x20, 0x22, 0x24, // and
                0x28, 0x2a, 0x2c, // sub
                0x30, 0x32, 0x34, // xor
                0x38, 0x3a, 0x3c, // cmp
                0x6a,             // push
                0x80, 0x88, 0x8a, 0xa0, 0xa2, 0xc6, // mov
                => true,
                // zig fmt: on
                else => false,
            },
        }
    }

    fn isSrcByteSized(opc: ParsedOpc) bool {
        if (opc.is_multi_byte) switch (opc.opc_byte_count) {
            2 => return switch (opc.bytes[1]) {
                0xbe => true,
                else => false,
            },
            3 => unreachable, // TODO
            else => unreachable, // impossible
        };
        switch (opc.enc) {
            .o => return false,
            .oi => return switch (opc.bytes[0] & o_mask) {
                0xb0 => true,
                else => false,
            },
            else => return switch (opc.bytes[0]) {
                // zig fmt: off
                0x00, 0x02, 0x04, // add
                0x08, 0x0a, 0x0c, // or
                0x10, 0x12, 0x14, // adc
                0x18, 0x1a, 0x1c, // sbb
                0x20, 0x22, 0x24, // and
                0x28, 0x2a, 0x2c, // sub
                0x30, 0x32, 0x34, // xor
                0x38, 0x3a, 0x3c, // cmp
                0x6a,             // push
                0x80, 0x88, 0x8a, 0xa0, 0xa2, 0xc6, // mov
                0x83,
                => true,
                // zig fmt: on
                else => false,
            },
        }
    }

    fn parse(reader: anytype) Error!ParsedOpc {
        const next_byte = try reader.readByte();
        var opc: ParsedOpc = blk: {
            switch (next_byte) {
                // Some M and MI encodings will be resolved fully later, once
                // we parse the ModRM byte.
                0x80, 0x81, 0x83, 0xc6, 0xc7 => break :blk ParsedOpc.wip(.mi),
                0xff => break :blk ParsedOpc.wip(.m),
                // Multi-byte opcodes will be resolved fully later, once
                // we parse additional bytes
                0x0f => break :blk ParsedOpc.multiByte(),
                // adc
                0x14, 0x15 => break :blk ParsedOpc.new(.adc, .i),
                0x10, 0x11 => break :blk ParsedOpc.new(.adc, .mr),
                0x12, 0x13 => break :blk ParsedOpc.new(.adc, .rm),
                // add
                0x04, 0x05 => break :blk ParsedOpc.new(.add, .i),
                0x00, 0x01 => break :blk ParsedOpc.new(.add, .mr),
                0x02, 0x03 => break :blk ParsedOpc.new(.add, .rm),
                // and
                0x24, 0x25 => break :blk ParsedOpc.new(.@"and", .i),
                0x20, 0x21 => break :blk ParsedOpc.new(.@"and", .mr),
                0x22, 0x23 => break :blk ParsedOpc.new(.@"and", .rm),
                // call
                0xe8 => break :blk ParsedOpc.new(.call, .m),
                // cmp
                0x3c, 0x3d => break :blk ParsedOpc.new(.cmp, .i),
                0x38, 0x39 => break :blk ParsedOpc.new(.cmp, .mr),
                0x3a, 0x3b => break :blk ParsedOpc.new(.cmp, .rm),
                // int3
                0xcc => break :blk ParsedOpc.new(.int3, .np),
                // mov
                0x88, 0x89, 0x8c => break :blk ParsedOpc.new(.mov, .mr),
                0x8a, 0x8b, 0x8e => break :blk ParsedOpc.new(.mov, .rm),
                0xa0, 0xa1 => break :blk ParsedOpc.new(.mov, .fd),
                0xa2, 0xa3 => break :blk ParsedOpc.new(.mov, .td),
                // movsxd
                0x63 => break :blk ParsedOpc.new(.movsxd, .rm),
                // nop
                0x90 => break :blk ParsedOpc.new(.nop, .np),
                // or
                0x0c, 0x0d => break :blk ParsedOpc.new(.@"or", .i),
                0x08, 0x09 => break :blk ParsedOpc.new(.@"or", .mr),
                0x0a, 0x0b => break :blk ParsedOpc.new(.@"or", .rm),
                // push
                0x68, 0x6a => break :blk ParsedOpc.new(.push, .i),
                // ret
                0xc3 => break :blk ParsedOpc.new(.ret, .np),
                // sbb
                0x1c, 0x1d => break :blk ParsedOpc.new(.sbb, .i),
                0x18, 0x19 => break :blk ParsedOpc.new(.sbb, .mr),
                0x1a, 0x1b => break :blk ParsedOpc.new(.sbb, .rm),
                // sub
                0x2c, 0x2d => break :blk ParsedOpc.new(.sub, .i),
                0x28, 0x29 => break :blk ParsedOpc.new(.sub, .mr),
                0x2a, 0x2b => break :blk ParsedOpc.new(.sub, .rm),
                // xor
                0x34, 0x35 => break :blk ParsedOpc.new(.xor, .i),
                0x30, 0x31 => break :blk ParsedOpc.new(.xor, .mr),
                0x32, 0x33 => break :blk ParsedOpc.new(.xor, .rm),
                // lea
                0x8d => break :blk ParsedOpc.new(.lea, .rm),
                // remaining
                else => {},
            }

            // check for O/OI encoding
            switch (next_byte & o_mask) {
                // mov
                0x50 => break :blk ParsedOpc.newWithExtra(.push, .o, @truncate(u3, next_byte)),
                0x58 => break :blk ParsedOpc.newWithExtra(.pop, .o, @truncate(u3, next_byte)),
                0xb0, 0xb8 => break :blk ParsedOpc.newWithExtra(.mov, .oi, @truncate(u3, next_byte)),
                // remaining
                else => |missing| {
                    std.log.err("unhandled opcode {x}", .{missing});
                    return error.Todo;
                },
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
                    opc.enc = .rm;
                    break;
                },

                else => return error.Todo,
            }
        }
        opc.is_wip = false;
    }

    fn new(tag: Instruction.Tag, enc: Instruction.Enc) ParsedOpc {
        return .{
            .tag = tag,
            .enc = enc,
            .extra = undefined,
            .is_wip = false,
            .is_multi_byte = false,
        };
    }

    fn newWithExtra(tag: Instruction.Tag, enc: Instruction.Enc, extra: u3) ParsedOpc {
        return .{
            .tag = tag,
            .enc = enc,
            .extra = extra,
            .is_wip = false,
            .is_multi_byte = false,
        };
    }

    fn wip(enc: Instruction.Enc) ParsedOpc {
        return .{
            .tag = undefined,
            .enc = enc,
            .extra = undefined,
            .is_wip = true,
            .is_multi_byte = false,
        };
    }

    fn multiByte() ParsedOpc {
        return .{
            .tag = undefined,
            .enc = undefined,
            .extra = undefined,
            .is_wip = true,
            .is_multi_byte = true,
        };
    }

    fn dstBitSize(self: ParsedOpc, rex: Rex, prefixes: LegacyPrefixes) u64 {
        switch (self.tag) {
            .movsx => {
                if (rex.w) return 64;
                if (prefixes.prefix_66) return 16;
                return 32;
            },
            else => {
                if (self.isDstByteSized()) return 8;
                if (rex.w) return 64;
                if (prefixes.prefix_66) return 16;
                switch (self.enc) {
                    .o, .m => return 64,
                    else => return 32,
                }
            },
        }
    }

    fn srcBitSize(self: ParsedOpc, rex: Rex, prefixes: LegacyPrefixes) ?u64 {
        switch (self.tag) {
            .movsx => {
                if (self.isSrcByteSized()) return 8;
                return 16;
            },
            .movsxd => return 32,
            else => switch (self.enc) {
                .rm, .mr, .oi, .fd, .td, .i, .mi => {
                    if (self.isSrcByteSized()) return 8;
                    if (rex.w) switch (self.enc) {
                        .i, .mi => return 32,
                        else => return 64,
                    };
                    if (rex.w) return 64;
                    if (prefixes.prefix_66) return 16;
                    return 32;
                },
                .o, .m, .np => return null,
            },
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
