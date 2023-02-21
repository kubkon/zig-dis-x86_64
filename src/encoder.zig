const std = @import("std");
const assert = std.debug.assert;
const math = std.math;

const bits = @import("bits.zig");
const encodings = @import("encodings.zig");
const sign = bits.sign;
const Encoding = encodings.Encoding;
const OperandKind = encodings.Operand;
const Memory = bits.Memory;
const Moffs = bits.Moffs;
pub const Mnemonic = encodings.Mnemonic;
const PtrSize = bits.PtrSize;
const Register = bits.Register;

pub const Instruction = struct {
    op1: Operand = .none,
    op2: Operand = .none,
    op3: Operand = .none,
    op4: Operand = .none,
    encoding: Encoding,

    pub const Operand = union(enum) {
        none,
        reg: Register,
        mem: Memory,
        moffs: Moffs,
        imm: u64,

        fn kind(op: Operand) OperandKind {
            switch (op) {
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

        /// Returns the bitsize of the operand.
        /// Asserts the operand is either register or memory.
        fn bitSize(op: Operand) u64 {
            return switch (op) {
                .none => unreachable,
                .reg => |reg| reg.bitSize(),
                .mem => |mem| mem.bitSize(),
                .moffs => unreachable,
                .imm => unreachable,
            };
        }

        /// Returns true if the operand is a segment register.
        /// Asserts the operand is either register or memory.
        fn isSegment(op: Operand) bool {
            return switch (op) {
                .none => unreachable,
                .reg => |reg| reg.isSegment(),
                .mem => |mem| mem.isSegment(),
                .moffs => true,
                .imm => unreachable,
            };
        }

        /// Returns true if the operand requires 64bit mode.
        /// Asserts the operand is either register or memory.
        fn is64BitMode(op: Operand) bool {
            switch (op) {
                .none => unreachable,
                .reg => |reg| {
                    if (reg.bitSize() > 64) return false;
                    if (reg.bitSize() == 64) return true;
                    return switch (reg) {
                        .ah, .ch, .dh, .bh => true,
                        else => false,
                    };
                },
                .mem => |mem| return mem.bitSize() == 64,
                .moffs => unreachable,
                .imm => unreachable,
            }
        }
    };

    pub fn new(args: struct {
        mnemonic: Mnemonic,
        op1: Operand = .none,
        op2: Operand = .none,
        op3: Operand = .none,
        op4: Operand = .none,
    }) !Instruction {
        const encoding = Encoding.findByMnemonic(args.mnemonic, .{
            .op1 = args.op1.kind(),
            .op2 = args.op2.kind(),
            .op3 = args.op3.kind(),
            .op4 = args.op4.kind(),
        }) orelse return error.InvalidInstruction;
        std.log.err("{}", .{encoding});
        return .{
            .op1 = args.op1,
            .op2 = args.op2,
            .op3 = args.op3,
            .op4 = args.op4,
            .encoding = encoding,
        };
    }

    pub fn encode(inst: Instruction, writer: anytype) !void {
        const encoder = Encoder(@TypeOf(writer)){ .writer = writer };
        const encoding = inst.encoding;
        const opcode = encoding.opcode();

        switch (encoding.op_en) {
            .np => try encodeOpcode(opcode, encoder),

            .fd => try encodeFd(opcode, inst.op1.reg, inst.op2.moffs, encoder),
            .td => try encodeFd(opcode, inst.op2.reg, inst.op1.moffs, encoder),

            .i => {
                if (encoding.op1.bitSize() == 16) {
                    try encoder.prefix16BitMode();
                }
                try encodeOpcode(opcode, encoder);
                try encodeImm(inst.op1.imm, encoding.op1, encoder);
            },

            .m, .mi => {
                const modrm_ext = encoding.modRmExt();

                var prefixes = LegacyPrefixes{};
                if (inst.op1.bitSize() == 16) {
                    prefixes.set16BitOverride();
                }
                if (inst.op1.isSegment()) {
                    const reg: Register = switch (inst.op1) {
                        .reg => |reg| reg,
                        .mem => |mem| mem.base.?,
                        else => unreachable,
                    };
                    prefixes.setSegmentOverride(reg);
                }
                try encoder.legacyPrefixes(prefixes);

                switch (inst.op1) {
                    .reg => |dst_reg| {
                        try encoder.rex(.{
                            .w = inst.op1.is64BitMode() and !encoding.mnemonic.defaultsTo64Bits(),
                            .b = dst_reg.isExtended(),
                        });
                        try encodeOpcode(opcode, encoder);
                        try encoder.modRm_direct(modrm_ext, dst_reg.lowEnc());
                    },
                    .mem => |dst_mem| {
                        try encoder.rex(.{
                            .w = inst.op1.is64BitMode() and !encoding.mnemonic.defaultsTo64Bits(),
                            .b = if (dst_mem.base) |base| base.isExtended() else false,
                            .x = if (dst_mem.scale_index) |si| si.index.isExtended() else false,
                        });
                        try encodeOpcode(opcode, encoder);
                        try dst_mem.encode(modrm_ext, encoder);
                    },
                    else => unreachable,
                }

                if (encoding.op_en == .mi) {
                    try encodeImm(inst.op2.imm, encoding.op2, encoder);
                }
            },

            .o, .oi => {
                assert(opcode.len == 1);
                if (inst.op1.bitSize() == 16) {
                    try encoder.prefix16BitMode();
                }
                try encoder.rex(.{
                    .w = inst.op1.is64BitMode() and !encoding.mnemonic.defaultsTo64Bits(),
                    .b = inst.op1.reg.isExtended(),
                });
                try encoder.opcode_withReg(opcode[0], inst.op1.reg.lowEnc());

                if (encoding.op_en == .oi) {
                    try encodeImm(inst.op2.imm, encoding.op2, encoder);
                }
            },

            .rm => try encodeRm(opcode, inst.op1, inst.op2, encoder),
            .mr => try encodeRm(opcode, inst.op2, inst.op1, encoder),
        }
    }

    fn encodeRm(opcode: []const u8, op1: Operand, op2: Operand, encoder: anytype) !void {
        assert(op1 == .reg);
        var prefixes = LegacyPrefixes{};
        if (op1.bitSize() == 16) {
            prefixes.set16BitOverride();
        }
        if (op2.isSegment()) {
            const r: Register = switch (op2) {
                .reg => |r| r,
                .mem => |m| m.base.?,
                else => unreachable,
            };
            prefixes.setSegmentOverride(r);
        }
        try encoder.legacyPrefixes(prefixes);
        switch (op2) {
            .reg => |r| {
                try encoder.rex(.{
                    .w = op1.is64BitMode(),
                    .r = op1.reg.isExtended(),
                    .b = r.isExtended(),
                });
                try encodeOpcode(opcode, encoder);
                try encoder.modRm_direct(op1.reg.lowEnc(), r.lowEnc());
            },
            .mem => |mem| {
                try encoder.rex(.{
                    .w = op1.is64BitMode(),
                    .r = op1.reg.isExtended(),
                    .b = if (mem.base) |base| base.isExtended() else false,
                    .x = if (mem.scale_index) |si| si.index.isExtended() else false,
                });
                try encodeOpcode(opcode, encoder);
                try mem.encode(op1.reg.lowEnc(), encoder);
            },
            else => unreachable,
        }
    }

    fn encodeFd(opcode: []const u8, reg: Register, moffs: Moffs, encoder: anytype) !void {
        assert(reg.to64() == .rax);
        var prefixes = LegacyPrefixes{};
        if (reg.bitSize() == 16) {
            prefixes.set16BitOverride();
        }
        prefixes.setSegmentOverride(moffs.seg);
        try encoder.legacyPrefixes(prefixes);
        try encoder.rex(.{
            .w = reg.bitSize() == 64,
        });
        try encodeOpcode(opcode, encoder);
        try encoder.imm64(moffs.offset);
    }

    fn encodeOpcode(opcode: []const u8, encoder: anytype) !void {
        for (opcode) |byte| {
            try encoder.opcode_1byte(byte);
        }
    }

    fn encodeImm(imm: u64, kind: OperandKind, encoder: anytype) !void {
        switch (kind) {
            .imm8 => try encoder.imm8(@bitCast(i8, @truncate(u8, imm))),
            .imm16 => try encoder.imm16(@bitCast(i16, @truncate(u16, imm))),
            .imm32 => try encoder.imm32(@bitCast(i32, @truncate(u32, imm))),
            .imm64 => try encoder.imm64(imm),
            else => unreachable,
        }
    }
};

pub const LegacyPrefixes = packed struct {
    /// LOCK
    prefix_f0: bool = false,
    /// REPNZ, REPNE, REP, Scalar Double-precision
    prefix_f2: bool = false,
    /// REPZ, REPE, REP, Scalar Single-precision
    prefix_f3: bool = false,

    /// CS segment override or Branch not taken
    prefix_2e: bool = false,
    /// SS segment override
    prefix_36: bool = false,
    /// ES segment override
    prefix_26: bool = false,
    /// FS segment override
    prefix_64: bool = false,
    /// GS segment override
    prefix_65: bool = false,

    /// Branch taken
    prefix_3e: bool = false,

    /// Address size override (enables 16 bit address size)
    prefix_67: bool = false,

    /// Operand size override (enables 16 bit operation)
    prefix_66: bool = false,

    padding: u5 = 0,

    pub fn setSegmentOverride(self: *LegacyPrefixes, reg: Register) void {
        assert(reg.isSegment());
        switch (reg) {
            .cs => self.prefix_2e = true,
            .ss => self.prefix_36 = true,
            .es => self.prefix_26 = true,
            .fs => self.prefix_64 = true,
            .gs => self.prefix_65 = true,
            .ds => {},
            else => unreachable,
        }
    }

    pub fn set16BitOverride(self: *LegacyPrefixes) void {
        self.prefix_66 = true;
    }
};

fn Encoder(comptime T: type) type {
    return struct {
        writer: T,

        const Self = @This();

        // --------
        // Prefixes
        // --------

        /// Encodes legacy prefixes
        pub fn legacyPrefixes(self: Self, prefixes: LegacyPrefixes) !void {
            if (@bitCast(u16, prefixes) != 0) {
                // Hopefully this path isn't taken very often, so we'll do it the slow way for now

                // LOCK
                if (prefixes.prefix_f0) try self.writer.writeByte(0xf0);
                // REPNZ, REPNE, REP, Scalar Double-precision
                if (prefixes.prefix_f2) try self.writer.writeByte(0xf2);
                // REPZ, REPE, REP, Scalar Single-precision
                if (prefixes.prefix_f3) try self.writer.writeByte(0xf3);

                // CS segment override or Branch not taken
                if (prefixes.prefix_2e) try self.writer.writeByte(0x2e);
                // DS segment override
                if (prefixes.prefix_36) try self.writer.writeByte(0x36);
                // ES segment override
                if (prefixes.prefix_26) try self.writer.writeByte(0x26);
                // FS segment override
                if (prefixes.prefix_64) try self.writer.writeByte(0x64);
                // GS segment override
                if (prefixes.prefix_65) try self.writer.writeByte(0x65);

                // Branch taken
                if (prefixes.prefix_3e) try self.writer.writeByte(0x3e);

                // Operand size override
                if (prefixes.prefix_66) try self.writer.writeByte(0x66);

                // Address size override
                if (prefixes.prefix_67) try self.writer.writeByte(0x67);
            }
        }

        /// Use 16 bit operand size
        ///
        /// Note that this flag is overridden by REX.W, if both are present.
        pub fn prefix16BitMode(self: Self) !void {
            try self.writer.writeByte(0x66);
        }

        /// Encodes a REX prefix byte given all the fields
        ///
        /// Use this byte whenever you need 64 bit operation,
        /// or one of reg, index, r/m, base, or opcode-reg might be extended.
        ///
        /// See struct `Rex` for a description of each field.
        ///
        /// Does not add a prefix byte if none of the fields are set!
        pub fn rex(self: Self, byte: Rex) !void {
            var value: u8 = 0b0100_0000;

            if (byte.w) value |= 0b1000;
            if (byte.r) value |= 0b0100;
            if (byte.x) value |= 0b0010;
            if (byte.b) value |= 0b0001;

            if (value != 0b0100_0000) {
                try self.writer.writeByte(value);
            }
        }

        // ------
        // Opcode
        // ------

        /// Encodes a 1 byte opcode
        pub fn opcode_1byte(self: Self, opcode: u8) !void {
            try self.writer.writeByte(opcode);
        }

        /// Encodes a 2 byte opcode
        ///
        /// e.g. IMUL has the opcode 0x0f 0xaf, so you use
        ///
        /// encoder.opcode_2byte(0x0f, 0xaf);
        pub fn opcode_2byte(self: Self, prefix: u8, opcode: u8) !void {
            try self.writer.writeAll(&.{ prefix, opcode });
        }

        /// Encodes a 3 byte opcode
        ///
        /// e.g. MOVSD has the opcode 0xf2 0x0f 0x10
        ///
        /// encoder.opcode_3byte(0xf2, 0x0f, 0x10);
        pub fn opcode_3byte(self: Self, prefix_1: u8, prefix_2: u8, opcode: u8) !void {
            try self.writer.writeAll(&.{ prefix_1, prefix_2, opcode });
        }

        /// Encodes a 1 byte opcode with a reg field
        ///
        /// Remember to add a REX prefix byte if reg is extended!
        pub fn opcode_withReg(self: Self, opcode: u8, reg: u3) !void {
            assert(opcode & 0b111 == 0);
            try self.writer.writeByte(opcode | reg);
        }

        // ------
        // ModR/M
        // ------

        /// Construct a ModR/M byte given all the fields
        ///
        /// Remember to add a REX prefix byte if reg or rm are extended!
        pub fn modRm(self: Self, mod: u2, reg_or_opx: u3, rm: u3) !void {
            try self.writer.writeByte(@as(u8, mod) << 6 | @as(u8, reg_or_opx) << 3 | rm);
        }

        /// Construct a ModR/M byte using direct r/m addressing
        /// r/m effective address: r/m
        ///
        /// Note reg's effective address is always just reg for the ModR/M byte.
        /// Remember to add a REX prefix byte if reg or rm are extended!
        pub fn modRm_direct(self: Self, reg_or_opx: u3, rm: u3) !void {
            try self.modRm(0b11, reg_or_opx, rm);
        }

        /// Construct a ModR/M byte using indirect r/m addressing
        /// r/m effective address: [r/m]
        ///
        /// Note reg's effective address is always just reg for the ModR/M byte.
        /// Remember to add a REX prefix byte if reg or rm are extended!
        pub fn modRm_indirectDisp0(self: Self, reg_or_opx: u3, rm: u3) !void {
            assert(rm != 4 and rm != 5);
            try self.modRm(0b00, reg_or_opx, rm);
        }

        /// Construct a ModR/M byte using indirect SIB addressing
        /// r/m effective address: [SIB]
        ///
        /// Note reg's effective address is always just reg for the ModR/M byte.
        /// Remember to add a REX prefix byte if reg or rm are extended!
        pub fn modRm_SIBDisp0(self: Self, reg_or_opx: u3) !void {
            try self.modRm(0b00, reg_or_opx, 0b100);
        }

        /// Construct a ModR/M byte using RIP-relative addressing
        /// r/m effective address: [RIP + disp32]
        ///
        /// Note reg's effective address is always just reg for the ModR/M byte.
        /// Remember to add a REX prefix byte if reg or rm are extended!
        pub fn modRm_RIPDisp32(self: Self, reg_or_opx: u3) !void {
            try self.modRm(0b00, reg_or_opx, 0b101);
        }

        /// Construct a ModR/M byte using indirect r/m with a 8bit displacement
        /// r/m effective address: [r/m + disp8]
        ///
        /// Note reg's effective address is always just reg for the ModR/M byte.
        /// Remember to add a REX prefix byte if reg or rm are extended!
        pub fn modRm_indirectDisp8(self: Self, reg_or_opx: u3, rm: u3) !void {
            assert(rm != 4);
            try self.modRm(0b01, reg_or_opx, rm);
        }

        /// Construct a ModR/M byte using indirect SIB with a 8bit displacement
        /// r/m effective address: [SIB + disp8]
        ///
        /// Note reg's effective address is always just reg for the ModR/M byte.
        /// Remember to add a REX prefix byte if reg or rm are extended!
        pub fn modRm_SIBDisp8(self: Self, reg_or_opx: u3) !void {
            try self.modRm(0b01, reg_or_opx, 0b100);
        }

        /// Construct a ModR/M byte using indirect r/m with a 32bit displacement
        /// r/m effective address: [r/m + disp32]
        ///
        /// Note reg's effective address is always just reg for the ModR/M byte.
        /// Remember to add a REX prefix byte if reg or rm are extended!
        pub fn modRm_indirectDisp32(self: Self, reg_or_opx: u3, rm: u3) !void {
            assert(rm != 4);
            try self.modRm(0b10, reg_or_opx, rm);
        }

        /// Construct a ModR/M byte using indirect SIB with a 32bit displacement
        /// r/m effective address: [SIB + disp32]
        ///
        /// Note reg's effective address is always just reg for the ModR/M byte.
        /// Remember to add a REX prefix byte if reg or rm are extended!
        pub fn modRm_SIBDisp32(self: Self, reg_or_opx: u3) !void {
            try self.modRm(0b10, reg_or_opx, 0b100);
        }

        // ---
        // SIB
        // ---

        /// Construct a SIB byte given all the fields
        ///
        /// Remember to add a REX prefix byte if index or base are extended!
        pub fn sib(self: Self, scale: u2, index: u3, base: u3) !void {
            try self.writer.writeByte(@as(u8, scale) << 6 | @as(u8, index) << 3 | base);
        }

        /// Construct a SIB byte with scale * index + base, no frills.
        /// r/m effective address: [base + scale * index]
        ///
        /// Remember to add a REX prefix byte if index or base are extended!
        pub fn sib_scaleIndexBase(self: Self, scale: u2, index: u3, base: u3) !void {
            assert(base != 5);

            try self.sib(scale, index, base);
        }

        /// Construct a SIB byte with scale * index + disp32
        /// r/m effective address: [scale * index + disp32]
        ///
        /// Remember to add a REX prefix byte if index or base are extended!
        pub fn sib_scaleIndexDisp32(self: Self, scale: u2, index: u3) !void {
            // scale is actually ignored
            // index = 4 means no index if and only if we haven't extended the register
            // TODO enforce this
            // base = 5 means no base, if mod == 0.
            try self.sib(scale, index, 5);
        }

        /// Construct a SIB byte with just base
        /// r/m effective address: [base]
        ///
        /// Remember to add a REX prefix byte if index or base are extended!
        pub fn sib_base(self: Self, base: u3) !void {
            assert(base != 5);

            // scale is actually ignored
            // index = 4 means no index
            try self.sib(0, 4, base);
        }

        /// Construct a SIB byte with just disp32
        /// r/m effective address: [disp32]
        ///
        /// Remember to add a REX prefix byte if index or base are extended!
        pub fn sib_disp32(self: Self) !void {
            // scale is actually ignored
            // index = 4 means no index
            // base = 5 means no base, if mod == 0.
            try self.sib(0, 4, 5);
        }

        /// Construct a SIB byte with scale * index + base + disp8
        /// r/m effective address: [base + scale * index + disp8]
        ///
        /// Remember to add a REX prefix byte if index or base are extended!
        pub fn sib_scaleIndexBaseDisp8(self: Self, scale: u2, index: u3, base: u3) !void {
            try self.sib(scale, index, base);
        }

        /// Construct a SIB byte with base + disp8, no index
        /// r/m effective address: [base + disp8]
        ///
        /// Remember to add a REX prefix byte if index or base are extended!
        pub fn sib_baseDisp8(self: Self, base: u3) !void {
            // scale is ignored
            // index = 4 means no index
            try self.sib(0, 4, base);
        }

        /// Construct a SIB byte with scale * index + base + disp32
        /// r/m effective address: [base + scale * index + disp32]
        ///
        /// Remember to add a REX prefix byte if index or base are extended!
        pub fn sib_scaleIndexBaseDisp32(self: Self, scale: u2, index: u3, base: u3) !void {
            try self.sib(scale, index, base);
        }

        /// Construct a SIB byte with base + disp32, no index
        /// r/m effective address: [base + disp32]
        ///
        /// Remember to add a REX prefix byte if index or base are extended!
        pub fn sib_baseDisp32(self: Self, base: u3) !void {
            // scale is ignored
            // index = 4 means no index
            try self.sib(0, 4, base);
        }

        // -------------------------
        // Trivial (no bit fiddling)
        // -------------------------

        /// Encode an 8 bit immediate
        ///
        /// It is sign-extended to 64 bits by the cpu.
        pub fn imm8(self: Self, imm: i8) !void {
            try self.writer.writeByte(@bitCast(u8, imm));
        }

        /// Encode an 8 bit displacement
        ///
        /// It is sign-extended to 64 bits by the cpu.
        pub fn disp8(self: Self, disp: i8) !void {
            try self.writer.writeByte(@bitCast(u8, disp));
        }

        /// Encode an 16 bit immediate
        ///
        /// It is sign-extended to 64 bits by the cpu.
        pub fn imm16(self: Self, imm: i16) !void {
            try self.writer.writeIntLittle(i16, imm);
        }

        /// Encode an 32 bit immediate
        ///
        /// It is sign-extended to 64 bits by the cpu.
        pub fn imm32(self: Self, imm: i32) !void {
            try self.writer.writeIntLittle(i32, imm);
        }

        /// Encode an 32 bit displacement
        ///
        /// It is sign-extended to 64 bits by the cpu.
        pub fn disp32(self: Self, disp: i32) !void {
            try self.writer.writeIntLittle(i32, disp);
        }

        /// Encode an 64 bit immediate
        ///
        /// It is sign-extended to 64 bits by the cpu.
        pub fn imm64(self: Self, imm: u64) !void {
            try self.writer.writeIntLittle(u64, imm);
        }
    };
}

pub const Rex = struct {
    w: bool = false,
    r: bool = false,
    x: bool = false,
    b: bool = false,

    pub fn isValid(byte: u8) bool {
        const mask: u8 = 0b0100_0000;
        return mask & byte != 0;
    }

    pub fn parse(byte: u8) ?Rex {
        const is_rex = @truncate(u4, byte >> 4) & 0b1111 == 0b0100;
        if (!is_rex) return null;

        const w: bool = byte & 0b1000 != 0;
        const r: bool = byte & 0b100 != 0;
        const x: bool = byte & 0b10 != 0;
        const b: bool = byte & 0b1 != 0;

        return Rex{
            .w = w,
            .r = r,
            .x = x,
            .b = b,
        };
    }
};
