const std = @import("std");
const assert = std.debug.assert;

const bits = @import("bits.zig");
const sign = bits.sign;
const Register = bits.Register;
const RegisterOrMemory = bits.RegisterOrMemory;

pub const Instruction = struct {
    tag: Tag,
    enc: Enc,
    data: Data,

    pub const Tag = enum {
        adc,
        add,
        @"and",
        cmp,
        mov,
        @"or",
        lea,

        fn encode(tag: Tag, enc: Enc, bit_size: u7, encoder: anytype) !void {
            if (bit_size == 8) switch (tag) {
                .adc => switch (enc) {
                    .oi => unreachable,
                    .mi, .mi8 => try encoder.opcode_1byte(0x80),
                    .rm => try encoder.opcode_1byte(0x12),
                    .mr => try encoder.opcode_1byte(0x10),
                },
                .add => switch (enc) {
                    .oi => unreachable, // does not support this encoding
                    .mi, .mi8 => try encoder.opcode_1byte(0x80),
                    .rm => try encoder.opcode_1byte(0x02),
                    .mr => try encoder.opcode_1byte(0x00),
                },
                .@"and" => switch (enc) {
                    .oi => unreachable, // does not support this encoding
                    .mi, .mi8 => try encoder.opcode_1byte(0x80),
                    .rm => try encoder.opcode_1byte(0x22),
                    .mr => try encoder.opcode_1byte(0x20),
                },
                .cmp => switch (enc) {
                    .oi => unreachable, // does not support this encoding
                    .mi, .mi8 => try encoder.opcode_1byte(0x80),
                    .rm => try encoder.opcode_1byte(0x3a),
                    .mr => try encoder.opcode_1byte(0x38),
                },
                .mov => switch (enc) {
                    .oi => unreachable, // use encodeWithReg instead
                    .mi => try encoder.opcode_1byte(0xc6),
                    .mi8 => unreachable, // does not support this encoding
                    .rm => try encoder.opcode_1byte(0x8a),
                    .mr => try encoder.opcode_1byte(0x88),
                },
                .@"or" => switch (enc) {
                    .oi => unreachable, // does not support this encoding
                    .mi, .mi8 => try encoder.opcode_1byte(0x80),
                    .rm => try encoder.opcode_1byte(0x0a),
                    .mr => try encoder.opcode_1byte(0x08),
                },
                .lea => unreachable, // does not support 8bit sizes
            } else switch (tag) {
                .adc => switch (enc) {
                    .oi => unreachable, // does not support this encoding
                    .mi => try encoder.opcode_1byte(0x81),
                    .mi8 => try encoder.opcode_1byte(0x83),
                    .rm => try encoder.opcode_1byte(0x13),
                    .mr => try encoder.opcode_1byte(0x11),
                },
                .add => switch (enc) {
                    .oi => unreachable, // does not support this encoding
                    .mi => try encoder.opcode_1byte(0x81),
                    .mi8 => try encoder.opcode_1byte(0x83),
                    .rm => try encoder.opcode_1byte(0x03),
                    .mr => try encoder.opcode_1byte(0x01),
                },
                .@"and" => switch (enc) {
                    .oi => unreachable, // does not support this encoding
                    .mi => try encoder.opcode_1byte(0x81),
                    .mi8 => try encoder.opcode_1byte(0x83),
                    .rm => try encoder.opcode_1byte(0x23),
                    .mr => try encoder.opcode_1byte(0x21),
                },
                .cmp => switch (enc) {
                    .oi => unreachable, // does not support this encoding
                    .mi => try encoder.opcode_1byte(0x81),
                    .mi8 => try encoder.opcode_1byte(0x83),
                    .rm => try encoder.opcode_1byte(0x3b),
                    .mr => try encoder.opcode_1byte(0x39),
                },
                .mov => switch (enc) {
                    .oi => unreachable, // use encodeWithReg instead
                    .mi => try encoder.opcode_1byte(0xc7),
                    .mi8 => unreachable, // does not support this encoding
                    .rm => try encoder.opcode_1byte(0x8b),
                    .mr => try encoder.opcode_1byte(0x89),
                },
                .@"or" => switch (enc) {
                    .oi => unreachable, // does not support this encoding
                    .mi => try encoder.opcode_1byte(0x81),
                    .mi8 => try encoder.opcode_1byte(0x83),
                    .rm => try encoder.opcode_1byte(0x0b),
                    .mr => try encoder.opcode_1byte(0x09),
                },
                .lea => switch (enc) {
                    .rm => try encoder.opcode_1byte(0x8d),
                    else => unreachable, // does not support different encodings
                },
            }
        }

        fn encodeWithReg(tag: Tag, reg: Register, encoder: anytype) !void {
            if (reg.bitSize() == 8) switch (tag) {
                .mov => try encoder.opcode_withReg(0xb0, reg.lowEnc()),
                else => unreachable,
            } else switch (tag) {
                .mov => try encoder.opcode_withReg(0xb8, reg.lowEnc()),
                else => unreachable,
            }
        }
    };

    pub const Enc = enum {
        oi,
        mi,
        mi8,
        mr,
        rm,
    };

    pub const Data = union {
        oi: Oi,
        mi: Mi,
        mr: Mr,
        rm: Rm,

        pub fn oi(reg: Register, imm: u64) Data {
            return .{
                .oi = .{
                    .reg = reg,
                    .imm = imm,
                },
            };
        }

        pub fn mi(reg_or_mem: RegisterOrMemory, imm: i32) Data {
            return .{
                .mi = .{
                    .reg_or_mem = reg_or_mem,
                    .imm = imm,
                },
            };
        }

        pub fn rm(reg: Register, reg_or_mem: RegisterOrMemory) Data {
            return .{
                .rm = .{
                    .reg = reg,
                    .reg_or_mem = reg_or_mem,
                },
            };
        }

        pub fn mr(reg_or_mem: RegisterOrMemory, reg: Register) Data {
            return .{
                .mr = .{
                    .reg_or_mem = reg_or_mem,
                    .reg = reg,
                },
            };
        }
    };

    pub const Oi = struct {
        reg: Register,
        imm: u64,
    };

    pub const Mi = struct {
        reg_or_mem: RegisterOrMemory,
        imm: i32,
    };

    pub const Mr = struct {
        reg_or_mem: RegisterOrMemory,
        reg: Register,
    };

    pub const Rm = struct {
        reg: Register,
        reg_or_mem: RegisterOrMemory,
    };

    pub fn encode(self: Instruction, writer: anytype) !void {
        const encoder = Encoder(@TypeOf(writer)){ .writer = writer };
        switch (self.enc) {
            .oi => {
                const oi = self.data.oi;
                const reg = oi.reg;
                const imm = oi.imm;
                if (reg.bitSize() == 16) {
                    try encoder.prefix16BitMode();
                }
                try encoder.rex(.{
                    .w = setRexWRegister(reg),
                    .b = reg.isExtended(),
                });
                try self.tag.encodeWithReg(reg, encoder);
                try encodeImmUnsigned(imm, reg.bitSize(), encoder);
            },
            .rm => {
                const rm = self.data.rm;
                const dst_reg = rm.reg;
                if (dst_reg.bitSize() == 16) {
                    try encoder.prefix16BitMode();
                }
                switch (rm.reg_or_mem) {
                    .reg => |src_reg| {
                        try encoder.rex(.{
                            .w = setRexWRegister(dst_reg) or setRexWRegister(src_reg),
                            .r = dst_reg.isExtended(),
                            .b = src_reg.isExtended(),
                        });
                        try self.tag.encode(.rm, dst_reg.bitSize(), encoder);
                        try encoder.modRm_direct(dst_reg.lowEnc(), src_reg.lowEnc());
                    },
                    .mem => |src_mem| {
                        switch (src_mem.base) {
                            .reg => |reg| {
                                try encoder.rex(.{
                                    .w = setRexWRegister(dst_reg),
                                    .r = dst_reg.isExtended(),
                                    .b = reg.isExtended(),
                                });
                            },
                            .rip, .seg => {
                                try encoder.rex(.{
                                    .w = setRexWRegister(dst_reg),
                                    .r = dst_reg.isExtended(),
                                });
                            },
                        }
                        try self.tag.encode(.rm, dst_reg.bitSize(), encoder);
                        try src_mem.encode(dst_reg.lowEnc(), encoder);
                    },
                }
            },
            .mr => {
                const mr = self.data.mr;
                const src_reg = mr.reg;
                switch (mr.reg_or_mem) {
                    .reg => |dst_reg| {
                        if (dst_reg.bitSize() == 16) {
                            try encoder.prefix16BitMode();
                        }
                        try encoder.rex(.{
                            .w = setRexWRegister(dst_reg) or setRexWRegister(src_reg),
                            .r = src_reg.isExtended(),
                            .b = dst_reg.isExtended(),
                        });
                        try self.tag.encode(.mr, dst_reg.bitSize(), encoder);
                        try encoder.modRm_direct(src_reg.lowEnc(), dst_reg.lowEnc());
                    },
                    .mem => |dst_mem| {
                        if (src_reg.bitSize() == 16) {
                            try encoder.prefix16BitMode();
                        }
                        switch (dst_mem.base) {
                            .reg => |dst_reg| {
                                try encoder.rex(.{
                                    .w = dst_mem.ptr_size == .qword or setRexWRegister(src_reg),
                                    .r = src_reg.isExtended(),
                                    .b = dst_reg.isExtended(),
                                });
                            },
                            .rip, .seg => {
                                try encoder.rex(.{
                                    .w = dst_mem.ptr_size == .qword or setRexWRegister(src_reg),
                                    .r = src_reg.isExtended(),
                                });
                            },
                        }
                        try self.tag.encode(.mr, dst_mem.bitSize(), encoder);
                        try dst_mem.encode(src_reg.lowEnc(), encoder);
                    },
                }
            },
            .mi, .mi8 => {
                const mi = self.data.mi;
                const modrm_ext: u3 = switch (self.tag) {
                    .add => 0,
                    .@"or" => 1,
                    .adc => 2,
                    .@"and" => 4,
                    .cmp => 7,
                    .mov => 0,
                    .lea => unreachable, // unsupported encoding
                };
                switch (mi.reg_or_mem) {
                    .reg => |dst_reg| {
                        if (dst_reg.bitSize() == 16) {
                            try encoder.prefix16BitMode();
                        }
                        try encoder.rex(.{
                            .w = setRexWRegister(dst_reg),
                            .b = dst_reg.isExtended(),
                        });
                        try self.tag.encode(self.enc, dst_reg.bitSize(), encoder);
                        try encoder.modRm_direct(modrm_ext, dst_reg.lowEnc());
                    },
                    .mem => |dst_mem| {
                        if (dst_mem.ptr_size == .word) {
                            try encoder.prefix16BitMode();
                        }
                        switch (dst_mem.base) {
                            .reg => |reg| {
                                try encoder.rex(.{
                                    .w = dst_mem.ptr_size == .qword,
                                    .b = reg.isExtended(),
                                });
                            },
                            .rip, .seg => {
                                try encoder.rex(.{
                                    .w = dst_mem.ptr_size == .qword,
                                });
                            },
                        }
                        try self.tag.encode(self.enc, dst_mem.bitSize(), encoder);
                        try dst_mem.encode(modrm_ext, encoder);
                    },
                }
                try encodeImmSigned(mi.imm, if (self.enc == .mi8) 8 else mi.reg_or_mem.bitSize(), encoder);
            },
        }
    }

    pub fn fmtPrint(self: Instruction, writer: anytype) !void {
        switch (self.tag) {
            .adc => try writer.writeAll("adc "),
            .add => try writer.writeAll("add "),
            .@"and" => try writer.writeAll("and "),
            .cmp => try writer.writeAll("cmp "),
            .mov => blk: {
                switch (self.enc) {
                    .oi => {
                        if (self.data.oi.reg.bitSize() == 64) {
                            break :blk try writer.writeAll("movabs ");
                        }
                    },
                    else => {},
                }
                try writer.writeAll("mov ");
            },
            .@"or" => try writer.writeAll("or "),
            .lea => try writer.writeAll("lea "),
        }

        switch (self.enc) {
            .oi => {
                const oi = self.data.oi;
                try oi.reg.fmtPrint(writer);
                try writer.writeAll(", ");

                if (oi.reg.bitSize() == 64) {
                    try writer.print("0x{x}", .{oi.imm});
                } else {
                    const imm_signed: i64 = @bitCast(i64, oi.imm);
                    const imm_abs: u64 = @intCast(u64, try std.math.absInt(imm_signed));
                    if (sign(imm_signed) < 0) {
                        try writer.writeByte('-');
                    }
                    try writer.print("0x{x}", .{imm_abs});
                }
            },
            .mi, .mi8 => {
                const mi = self.data.mi;
                try mi.reg_or_mem.fmtPrint(writer);
                try writer.writeAll(", ");
                const imm_signed: i32 = @bitCast(i32, mi.imm);
                const imm_abs: u32 = @intCast(u32, try std.math.absInt(imm_signed));
                if (sign(imm_signed) < 0) {
                    try writer.writeByte('-');
                }
                try writer.print("0x{x}", .{imm_abs});
            },
            .rm => {
                const rm = self.data.rm;
                try rm.reg.fmtPrint(writer);
                try writer.writeAll(", ");
                try rm.reg_or_mem.fmtPrint(writer);
            },
            .mr => {
                const mr = self.data.mr;
                try mr.reg_or_mem.fmtPrint(writer);
                try writer.writeAll(", ");
                try mr.reg.fmtPrint(writer);
            },
        }
    }
};

inline fn setRexWRegister(reg: Register) bool {
    if (reg.bitSize() > 64) return false;
    if (reg.bitSize() == 64) return true;
    return switch (reg) {
        .ah, .ch, .dh, .bh => true,
        else => false,
    };
}

inline fn encodeImmUnsigned(imm: u64, bit_size: u7, encoder: anytype) !void {
    switch (bit_size) {
        8 => try encoder.imm8(@bitCast(i8, @truncate(u8, imm))),
        16 => try encoder.imm16(@bitCast(i16, @truncate(u16, imm))),
        32 => try encoder.imm32(@bitCast(i32, @truncate(u32, imm))),
        64 => try encoder.imm64(imm),
        else => unreachable,
    }
}

inline fn encodeImmSigned(imm: i32, bit_size: u7, encoder: anytype) !void {
    switch (bit_size) {
        8 => try encoder.imm8(@truncate(i8, imm)),
        16 => try encoder.imm16(@truncate(i16, imm)),
        32, 64 => try encoder.imm32(imm),
        else => unreachable,
    }
}

fn Encoder(comptime T: type) type {
    return struct {
        writer: T,

        const Self = @This();

        // --------
        // Prefixes
        // --------

        pub const LegacyPrefixes = packed struct {
            /// LOCK
            prefix_f0: bool = false,
            /// REPNZ, REPNE, REP, Scalar Double-precision
            prefix_f2: bool = false,
            /// REPZ, REPE, REP, Scalar Single-precision
            prefix_f3: bool = false,

            /// CS segment override or Branch not taken
            prefix_2e: bool = false,
            /// DS segment override
            prefix_36: bool = false,
            /// ES segment override
            prefix_26: bool = false,
            /// FS segment override
            prefix_64: bool = false,
            /// GS segment override
            prefix_65: bool = false,

            /// Branch taken
            prefix_3e: bool = false,

            /// Operand size override (enables 16 bit operation)
            prefix_66: bool = false,

            /// Address size override (enables 16 bit address size)
            prefix_67: bool = false,

            padding: u5 = 0,
        };

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
            assert(index != 4);

            // scale is actually ignored
            // index = 4 means no index
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
