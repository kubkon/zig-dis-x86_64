const std = @import("std");
const assert = std.debug.assert;
const math = std.math;

const bits = @import("bits.zig");
const sign = bits.sign;
const Memory = bits.Memory;
const PtrSize = bits.PtrSize;
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
        ret,
        syscall,

        fn encode(tag: Tag, enc: Enc, bit_size: u64, encoder: anytype) !void {
            if (enc == .np) {
                return switch (tag) {
                    .int3 => try encoder.opcode_1byte(0xcc),
                    .ret => try encoder.opcode_1byte(0xc3),
                    .syscall => try encoder.opcode_2byte(0x0f, 0x05),
                    else => unreachable, // invalid tag for np encoding
                };
            }

            if (bit_size == 8) switch (tag) {
                .adc => switch (enc) {
                    .i => try encoder.opcode_1byte(0x14),
                    .mi, .mi8 => try encoder.opcode_1byte(0x80),
                    .rm => try encoder.opcode_1byte(0x12),
                    .mr => try encoder.opcode_1byte(0x10),
                    else => unreachable, // does not support this encoding
                },

                .add => switch (enc) {
                    .i => try encoder.opcode_1byte(0x04),
                    .mi, .mi8 => try encoder.opcode_1byte(0x80),
                    .rm => try encoder.opcode_1byte(0x02),
                    .mr => try encoder.opcode_1byte(0x00),
                    else => unreachable, // does not support this encoding
                },

                .@"and" => switch (enc) {
                    .i => try encoder.opcode_1byte(0x24),
                    .mi, .mi8 => try encoder.opcode_1byte(0x80),
                    .rm => try encoder.opcode_1byte(0x22),
                    .mr => try encoder.opcode_1byte(0x20),
                    else => unreachable, // does not support this encoding
                },

                .cmp => switch (enc) {
                    .i => try encoder.opcode_1byte(0x3c),
                    .mi, .mi8 => try encoder.opcode_1byte(0x80),
                    .rm => try encoder.opcode_1byte(0x3a),
                    .mr => try encoder.opcode_1byte(0x38),
                    else => unreachable, // does not support this encoding
                },

                .mov => switch (enc) {
                    .fd => try encoder.opcode_1byte(0xa0),
                    .td => try encoder.opcode_1byte(0xa2),
                    .oi => unreachable, // use encodeWithReg instead
                    .mi => try encoder.opcode_1byte(0xc6),
                    .rm => try encoder.opcode_1byte(0x8a),
                    .mr => try encoder.opcode_1byte(0x88),
                    else => unreachable, // does not support this encoding
                },

                .movsx => switch (enc) {
                    .rm => try encoder.opcode_2byte(0x0f, 0xbe),
                    else => unreachable, // does not support this encoding
                },

                .@"or" => switch (enc) {
                    .i => try encoder.opcode_1byte(0x0c),
                    .mi, .mi8 => try encoder.opcode_1byte(0x80),
                    .rm => try encoder.opcode_1byte(0x0a),
                    .mr => try encoder.opcode_1byte(0x08),
                    else => unreachable, // does not support this encoding
                },

                .push => switch (enc) {
                    .i => try encoder.opcode_1byte(0x6a),
                    else => unreachable, // does not support this encoding
                },

                .sbb => switch (enc) {
                    .i => try encoder.opcode_1byte(0x1c),
                    .mi, .mi8 => try encoder.opcode_1byte(0x80),
                    .rm => try encoder.opcode_1byte(0x1a),
                    .mr => try encoder.opcode_1byte(0x18),
                    else => unreachable, // does not support this encoding
                },

                .sub => switch (enc) {
                    .i => try encoder.opcode_1byte(0x2c),
                    .mi, .mi8 => try encoder.opcode_1byte(0x80),
                    .rm => try encoder.opcode_1byte(0x2a),
                    .mr => try encoder.opcode_1byte(0x28),
                    else => unreachable, // does not support this encoding
                },

                .xor => switch (enc) {
                    .i => try encoder.opcode_1byte(0x34),
                    .mi, .mi8 => try encoder.opcode_1byte(0x80),
                    .rm => try encoder.opcode_1byte(0x32),
                    .mr => try encoder.opcode_1byte(0x30),
                    else => unreachable, // does not support this encoding
                },

                .call,
                .int3,
                .lea,
                .movsxd,
                .pop,
                .ret,
                .syscall,
                => unreachable,
            } else switch (tag) {
                .adc => switch (enc) {
                    .i => try encoder.opcode_1byte(0x15),
                    .mi => try encoder.opcode_1byte(0x81),
                    .mi8 => try encoder.opcode_1byte(0x83),
                    .rm => try encoder.opcode_1byte(0x13),
                    .mr => try encoder.opcode_1byte(0x11),
                    else => unreachable, // does not support this encoding
                },

                .add => switch (enc) {
                    .i => try encoder.opcode_1byte(0x05),
                    .mi => try encoder.opcode_1byte(0x81),
                    .mi8 => try encoder.opcode_1byte(0x83),
                    .rm => try encoder.opcode_1byte(0x03),
                    .mr => try encoder.opcode_1byte(0x01),
                    else => unreachable, // does not support this encoding
                },

                .@"and" => switch (enc) {
                    .i => try encoder.opcode_1byte(0x25),
                    .mi => try encoder.opcode_1byte(0x81),
                    .mi8 => try encoder.opcode_1byte(0x83),
                    .rm => try encoder.opcode_1byte(0x23),
                    .mr => try encoder.opcode_1byte(0x21),
                    else => unreachable, // does not support this encoding
                },

                .call => switch (enc) {
                    .m => try encoder.opcode_1byte(0xff),
                    .m_rel => try encoder.opcode_1byte(0xe8),
                    else => unreachable, // does not support this encoding
                },

                .cmp => switch (enc) {
                    .i => try encoder.opcode_1byte(0x3d),
                    .mi => try encoder.opcode_1byte(0x81),
                    .mi8 => try encoder.opcode_1byte(0x83),
                    .rm => try encoder.opcode_1byte(0x3b),
                    .mr => try encoder.opcode_1byte(0x39),
                    else => unreachable, // does not support this encoding
                },

                .mov => switch (enc) {
                    .fd => try encoder.opcode_1byte(0xa1),
                    .td => try encoder.opcode_1byte(0xa3),
                    .mi => try encoder.opcode_1byte(0xc7),
                    .mi8 => unreachable, // does not support this encoding
                    .rm => try encoder.opcode_1byte(0x8b),
                    .mr => try encoder.opcode_1byte(0x89),
                    else => unreachable, // does not support this encoding
                },

                .movsx => switch (enc) {
                    .rm => try encoder.opcode_2byte(0x0f, 0xbf),
                    else => unreachable, // does not support this encoding
                },

                .movsxd => switch (enc) {
                    .rm => try encoder.opcode_1byte(0x63),
                    else => unreachable, // does not support this encoding
                },

                .@"or" => switch (enc) {
                    .i => try encoder.opcode_1byte(0x0d),
                    .mi => try encoder.opcode_1byte(0x81),
                    .mi8 => try encoder.opcode_1byte(0x83),
                    .rm => try encoder.opcode_1byte(0x0b),
                    .mr => try encoder.opcode_1byte(0x09),
                    else => unreachable, // does not support this encoding
                },

                .lea => switch (enc) {
                    .rm => try encoder.opcode_1byte(0x8d),
                    else => unreachable, // does not support different encodings
                },

                .push => switch (enc) {
                    .i => try encoder.opcode_1byte(0x68),
                    else => unreachable, // does not support this encoding
                },

                .sbb => switch (enc) {
                    .i => try encoder.opcode_1byte(0x1d),
                    .mi => try encoder.opcode_1byte(0x81),
                    .mi8 => try encoder.opcode_1byte(0x83),
                    .rm => try encoder.opcode_1byte(0x1b),
                    .mr => try encoder.opcode_1byte(0x19),
                    else => unreachable, // does not support this encoding
                },

                .sub => switch (enc) {
                    .i => try encoder.opcode_1byte(0x2d),
                    .mi => try encoder.opcode_1byte(0x81),
                    .mi8 => try encoder.opcode_1byte(0x83),
                    .rm => try encoder.opcode_1byte(0x2b),
                    .mr => try encoder.opcode_1byte(0x29),
                    else => unreachable, // does not support this encoding
                },

                .xor => switch (enc) {
                    .i => try encoder.opcode_1byte(0x35),
                    .mi => try encoder.opcode_1byte(0x81),
                    .mi8 => try encoder.opcode_1byte(0x83),
                    .rm => try encoder.opcode_1byte(0x33),
                    .mr => try encoder.opcode_1byte(0x31),
                    else => unreachable, // does not support this encoding
                },

                .int3,
                .pop,
                .ret,
                .syscall,
                => unreachable,
            }
        }

        fn modRmExt(tag: Tag, enc: Enc) ?u3 {
            switch (enc) {
                .mi, .mi8 => return switch (tag) {
                    .add, .mov => 0,
                    .@"or" => 1,
                    .adc => 2,
                    .sbb => 3,
                    .@"and" => 4,
                    .sub => 5,
                    .xor => 6,
                    .cmp => 7,

                    else => unreachable, // unsupported encoding
                },

                .m => return switch (tag) {
                    .call => 2,

                    else => unreachable, // unsupported encoding
                },

                else => unreachable,
            }
        }

        fn encodeWithReg(tag: Tag, reg: Register, encoder: anytype) !void {
            if (reg.bitSize() == 8) switch (tag) {
                .mov => try encoder.opcode_withReg(0xb0, reg.lowEnc()),
                else => unreachable,
            } else switch (tag) {
                .mov => try encoder.opcode_withReg(0xb8, reg.lowEnc()),
                .push => try encoder.opcode_withReg(0x50, reg.lowEnc()),
                .pop => try encoder.opcode_withReg(0x58, reg.lowEnc()),
                else => unreachable,
            }
        }
    };

    pub const Enc = enum {
        np,
        o,
        i,
        m,
        m_rel,
        fd,
        td,
        oi,
        mi,
        mi8,
        mr,
        rm,
    };

    pub const Data = union {
        np: void,
        o: O,
        i: I,
        m: M,
        m_rel: MRel,
        fd: Fd,
        oi: Oi,
        mi: Mi,
        mr: Mr,
        rm: Rm,

        pub fn np() Data {
            return .{ .np = {} };
        }

        pub fn o(reg: Register) Data {
            return .{ .o = .{ .reg = reg } };
        }

        pub fn i(imm: i32, bit_size: ?u64) Data {
            return .{ .i = .{ .bit_size = bit_size, .imm = imm } };
        }

        pub fn m(reg_or_mem: RegisterOrMemory) Data {
            return .{ .m = .{ .reg_or_mem = reg_or_mem } };
        }

        pub fn mRel(imm: i32) Data {
            return .{ .m_rel = .{ .imm = imm } };
        }

        pub fn fd(reg: Register, imm: u64, ptr_size: PtrSize) Data {
            return .{ .fd = .{ .ptr_size = ptr_size, .imm = imm, .reg = reg } };
        }

        pub fn oi(reg: Register, imm: u64) Data {
            return .{ .oi = .{ .reg = reg, .imm = imm } };
        }

        pub fn mi(reg_or_mem: RegisterOrMemory, imm: i32) Data {
            return .{ .mi = .{ .reg_or_mem = reg_or_mem, .imm = imm } };
        }

        pub fn rm(reg: Register, reg_or_mem: RegisterOrMemory) Data {
            return .{ .rm = .{ .reg = reg, .reg_or_mem = reg_or_mem } };
        }

        pub fn mr(reg_or_mem: RegisterOrMemory, reg: Register) Data {
            return .{ .mr = .{ .reg_or_mem = reg_or_mem, .reg = reg } };
        }
    };

    pub const O = struct {
        reg: Register,
    };

    pub const I = struct {
        /// null implies the bit size will be auto-inferred from the immediate.
        /// Note that auto-inferrence will never promote the instruction to 64bits.
        /// For that, set the bit size explicitly.
        bit_size: ?u64 = null,
        imm: i32,
    };

    pub const M = struct {
        reg_or_mem: RegisterOrMemory,
    };

    pub const MRel = struct {
        imm: i32,
    };

    pub const Fd = struct {
        imm: u64,
        /// Destination segment register.
        reg: Register,
        /// Size of the data to transfer.
        ptr_size: PtrSize,
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
            .np => {
                try self.tag.encode(.np, undefined, encoder);
            },

            .o => {
                const reg = self.data.o.reg;
                const bit_size = reg.bitSize();
                if (bit_size == 16) {
                    try encoder.prefix16BitMode();
                }
                try encoder.rex(.{
                    .w = false,
                    .b = reg.isExtended(),
                });
                try self.tag.encodeWithReg(reg, encoder);
            },

            .i => {
                const i = self.data.i;
                const imm = i.imm;
                const bit_size = if (i.bit_size) |bs| bs else bitSizeFromImm(@bitCast(u32, imm));
                if (bit_size == 16) {
                    try encoder.prefix16BitMode();
                }
                try encoder.rex(.{
                    .w = bit_size == 64,
                });
                try self.tag.encode(.i, bit_size, encoder);
                try encodeImmSigned(imm, bit_size, encoder);
            },

            .m_rel => {
                const imm = self.data.m_rel.imm;
                try self.tag.encode(.m_rel, 32, encoder);
                try encodeImmSigned(imm, 32, encoder);
            },

            .m => {
                const reg_or_mem = self.data.m.reg_or_mem;
                const modrm_ext = self.tag.modRmExt(self.enc).?;
                const bit_size = reg_or_mem.bitSize();
                if (bit_size == 16) {
                    try encoder.prefix16BitMode();
                }
                switch (reg_or_mem) {
                    .reg => |reg| {
                        try encoder.rex(.{
                            .w = false,
                            .b = reg.isExtended(),
                        });
                        try self.tag.encode(self.enc, bit_size, encoder);
                        try encoder.modRm_direct(modrm_ext, reg.lowEnc());
                    },
                    .mem => |mem| {
                        try encoder.rex(.{
                            .w = false,
                            .b = if (mem.base) |base| base.isExtended() else false,
                            .x = if (mem.scale_index) |si| si.index.isExtended() else false,
                        });
                        try self.tag.encode(self.enc, bit_size, encoder);
                        try mem.encode(modrm_ext, encoder);
                    },
                }
            },

            .fd, .td => {
                const fd = self.data.fd;
                const reg = fd.reg;
                const imm = fd.imm;
                if (reg.class() != .seg) {
                    return error.WrongRegisterClass;
                }
                var prefixes = LegacyPrefixes{};
                if (fd.ptr_size == .word) {
                    prefixes.set16BitOverride();
                }
                prefixes.setSegmentOverride(reg);
                try encoder.legacyPrefixes(prefixes);
                try encoder.rex(.{
                    .w = fd.ptr_size == .qword,
                });
                const bit_size = fd.ptr_size.bitSize();
                try self.tag.encode(self.enc, bit_size, encoder);
                try encoder.imm64(imm);
            },

            .oi => {
                const oi = self.data.oi;
                const reg = oi.reg;
                const imm = oi.imm;
                const bit_size = reg.bitSize();
                if (bit_size == 16) {
                    try encoder.prefix16BitMode();
                }
                try encoder.rex(.{
                    .w = setRexWRegister(reg),
                    .b = reg.isExtended(),
                });
                try self.tag.encodeWithReg(reg, encoder);
                try encodeImmUnsigned(imm, bit_size, encoder);
            },

            .rm => {
                const rm = self.data.rm;
                const dst_reg = rm.reg;
                var prefixes = LegacyPrefixes{};
                if (dst_reg.bitSize() == 16) {
                    prefixes.set16BitOverride();
                }
                if (rm.reg_or_mem.isSegment()) {
                    const reg: Register = switch (rm.reg_or_mem) {
                        .reg => |r| r,
                        .mem => |m| m.base.?,
                    };
                    prefixes.setSegmentOverride(reg);
                }
                try encoder.legacyPrefixes(prefixes);
                switch (rm.reg_or_mem) {
                    .reg => |src_reg| {
                        try encoder.rex(.{
                            .w = setRexWRegister(dst_reg) or setRexWRegister(src_reg),
                            .r = dst_reg.isExtended(),
                            .b = src_reg.isExtended(),
                        });
                        try self.tag.encode(.rm, src_reg.bitSize(), encoder);
                        try encoder.modRm_direct(dst_reg.lowEnc(), src_reg.lowEnc());
                    },
                    .mem => |src_mem| {
                        try encoder.rex(.{
                            .w = setRexWRegister(dst_reg),
                            .r = dst_reg.isExtended(),
                            .b = if (src_mem.base) |base| base.isExtended() else false,
                            .x = if (src_mem.scale_index) |si| si.index.isExtended() else false,
                        });
                        try self.tag.encode(.rm, src_mem.bitSize(), encoder);
                        try src_mem.encode(dst_reg.lowEnc(), encoder);
                    },
                }
            },

            .mr => {
                const mr = self.data.mr;
                const src_reg = mr.reg;
                const bit_size = src_reg.bitSize();
                var prefixes = LegacyPrefixes{};
                if (bit_size == 16) {
                    prefixes.set16BitOverride();
                }
                if (mr.reg_or_mem.isSegment()) {
                    const reg: Register = switch (mr.reg_or_mem) {
                        .reg => |r| r,
                        .mem => |m| m.base.?,
                    };
                    prefixes.setSegmentOverride(reg);
                }
                try encoder.legacyPrefixes(prefixes);
                switch (mr.reg_or_mem) {
                    .reg => |dst_reg| {
                        try encoder.rex(.{
                            .w = setRexWRegister(dst_reg) or setRexWRegister(src_reg),
                            .r = src_reg.isExtended(),
                            .b = dst_reg.isExtended(),
                        });
                        try self.tag.encode(.mr, bit_size, encoder);
                        try encoder.modRm_direct(src_reg.lowEnc(), dst_reg.lowEnc());
                    },
                    .mem => |dst_mem| {
                        try encoder.rex(.{
                            .w = dst_mem.ptr_size == .qword or setRexWRegister(src_reg),
                            .r = src_reg.isExtended(),
                            .b = if (dst_mem.base) |base| base.isExtended() else false,
                            .x = if (dst_mem.scale_index) |si| si.index.isExtended() else false,
                        });
                        try self.tag.encode(.mr, bit_size, encoder);
                        try dst_mem.encode(src_reg.lowEnc(), encoder);
                    },
                }
            },

            .mi, .mi8 => {
                const mi = self.data.mi;
                const modrm_ext = self.tag.modRmExt(self.enc).?;
                var prefixes = LegacyPrefixes{};
                const bit_size = mi.reg_or_mem.bitSize();
                if (bit_size == 16) {
                    prefixes.set16BitOverride();
                }
                if (mi.reg_or_mem.isSegment()) {
                    const reg: Register = switch (mi.reg_or_mem) {
                        .reg => |r| r,
                        .mem => |m| m.base.?,
                    };
                    prefixes.setSegmentOverride(reg);
                }
                try encoder.legacyPrefixes(prefixes);
                switch (mi.reg_or_mem) {
                    .reg => |dst_reg| {
                        try encoder.rex(.{
                            .w = setRexWRegister(dst_reg),
                            .b = dst_reg.isExtended(),
                        });
                        try self.tag.encode(self.enc, bit_size, encoder);
                        try encoder.modRm_direct(modrm_ext, dst_reg.lowEnc());
                    },
                    .mem => |dst_mem| {
                        try encoder.rex(.{
                            .w = dst_mem.ptr_size == .qword,
                            .b = if (dst_mem.base) |base| base.isExtended() else false,
                            .x = if (dst_mem.scale_index) |si| si.index.isExtended() else false,
                        });
                        try self.tag.encode(self.enc, bit_size, encoder);
                        try dst_mem.encode(modrm_ext, encoder);
                    },
                }
                try encodeImmSigned(mi.imm, if (self.enc == .mi8) 8 else mi.reg_or_mem.bitSize(), encoder);
            },
        }
    }

    fn fmtImm(imm: i32, writer: anytype) !void {
        const imm_abs: u32 = @intCast(u32, try math.absInt(imm));
        if (sign(imm) < 0) {
            try writer.writeByte('-');
        }
        try writer.print("0x{x}", .{imm_abs});
    }

    pub fn fmtPrint(self: Instruction, writer: anytype) !void {
        switch (self.tag) {
            .mov => switch (self.enc) {
                .fd, .td => try writer.writeAll("movabs"),
                .oi => if (self.data.oi.reg.bitSize() == 64)
                    try writer.writeAll("movabs")
                else
                    try writer.writeAll("mov"),
                else => try writer.writeAll("mov"),
            },
            else => try writer.print("{s}", .{@tagName(self.tag)}),
        }
        try writer.writeByte(' ');

        switch (self.enc) {
            .np => {},

            .o => {
                const reg = self.data.o.reg;
                try reg.fmtPrint(writer);
            },

            .i => {
                const i = self.data.i;
                const bit_size = if (i.bit_size) |bs| bs else bitSizeFromImm(@bitCast(u32, i.imm));
                const dst_reg = Register.rax.toBitSize(bit_size);
                try dst_reg.fmtPrint(writer);
                try writer.writeAll(", ");
                try fmtImm(i.imm, writer);
            },

            .m_rel => {
                const imm = self.data.m_rel.imm;
                try fmtImm(imm, writer);
            },

            .m => {
                const reg_or_mem = self.data.m.reg_or_mem;
                try reg_or_mem.fmtPrint(writer);
            },

            .fd => {
                const fd = self.data.fd;
                const reg = fd.reg;
                const imm = fd.imm;
                if (reg.class() != .seg) {
                    return error.WrongRegisterClass;
                }
                const dst_reg = Register.rax.toBitSize(fd.ptr_size.bitSize());
                try dst_reg.fmtPrint(writer);
                try writer.writeAll(", ");
                try reg.fmtPrint(writer);
                try writer.print(":0x{x}", .{imm});
            },

            .td => {
                const fd = self.data.fd;
                const reg = fd.reg;
                const imm = fd.imm;
                if (reg.class() != .seg) {
                    return error.WrongRegisterClass;
                }
                const dst_reg = Register.rax.toBitSize(fd.ptr_size.bitSize());
                try reg.fmtPrint(writer);
                try writer.print(":0x{x}", .{imm});
                try writer.writeAll(", ");
                try dst_reg.fmtPrint(writer);
            },

            .oi => {
                const oi = self.data.oi;
                try oi.reg.fmtPrint(writer);
                try writer.writeAll(", ");

                if (oi.reg.bitSize() == 64) {
                    try writer.print("0x{x}", .{oi.imm});
                } else {
                    const imm_signed: i64 = @bitCast(i64, oi.imm);
                    const imm_abs: u64 = @intCast(u64, try math.absInt(imm_signed));
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
                const imm_abs: u32 = @intCast(u32, try math.absInt(imm_signed));
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

fn setRexWRegister(reg: Register) bool {
    if (reg.bitSize() > 64) return false;
    if (reg.bitSize() == 64) return true;
    return switch (reg) {
        .ah, .ch, .dh, .bh => true,
        else => false,
    };
}

fn encodeImmUnsigned(imm: u64, bit_size: u64, encoder: anytype) !void {
    switch (bit_size) {
        8 => try encoder.imm8(@bitCast(i8, @truncate(u8, imm))),
        16 => try encoder.imm16(@bitCast(i16, @truncate(u16, imm))),
        32 => try encoder.imm32(@bitCast(i32, @truncate(u32, imm))),
        64 => try encoder.imm64(imm),
        else => unreachable,
    }
}

fn encodeImmSigned(imm: i32, bit_size: u64, encoder: anytype) !void {
    switch (bit_size) {
        8 => try encoder.imm8(@truncate(i8, imm)),
        16 => try encoder.imm16(@truncate(i16, imm)),
        32, 64 => try encoder.imm32(imm),
        else => unreachable,
    }
}

fn bitSizeFromImm(imm: u64) u64 {
    if (math.cast(u8, imm)) |_| return 8;
    if (math.cast(u16, imm)) |_| return 16;
    if (math.cast(u32, imm)) |_| return 32;
    return 64;
}

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
