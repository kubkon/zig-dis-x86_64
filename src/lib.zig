const std = @import("std");
const assert = std.debug.assert;
const math = std.math;
const testing = std.testing;

const Allocator = std.mem.Allocator;

pub const Register = enum(u7) {
    // zig fmt: off
    rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi,
    r8, r9, r10, r11, r12, r13, r14, r15,

    eax, ecx, edx, ebx, esp, ebp, esi, edi,
    r8d, r9d, r10d, r11d, r12d, r13d, r14d, r15d,

    ax, cx, dx, bx, sp, bp, si, di,
    r8w, r9w, r10w, r11w, r12w, r13w, r14w, r15w,

    al, cl, dl, bl, ah, ch, dh, bh,
    r8b, r9b, r10b, r11b, r12b, r13b, r14b, r15b,
    // zig fmt: on

    pub fn fromLowEnc(low_enc: u3, is_extended: bool, bitsize: u7) Register {
        const reg_id: u4 = @intCast(u4, @boolToInt(is_extended)) << 3 | low_enc;
        const unsized = @intToEnum(Register, reg_id);
        return switch (bitsize) {
            8 => unsized.to8(),
            16 => unsized.to16(),
            32 => unsized.to32(),
            64 => unsized.to64(),
            else => unreachable,
        };
    }

    pub fn id(self: Register) u4 {
        return switch (@enumToInt(self)) {
            0...63 => @truncate(u4, @enumToInt(self)),
            else => unreachable,
        };
    }

    pub fn size(self: Register) u7 {
        return switch (@enumToInt(self)) {
            0...15 => 64,
            16...31 => 32,
            32...47 => 16,
            48...63 => 8,
            else => unreachable,
        };
    }

    pub fn isExtended(self: Register) bool {
        return @enumToInt(self) & 0x08 != 0;
    }

    pub fn enc(self: Register) u4 {
        return @truncate(u4, @enumToInt(self));
    }

    pub fn lowEnc(self: Register) u3 {
        return @truncate(u3, @enumToInt(self));
    }

    pub fn to64(self: Register) Register {
        return @intToEnum(Register, self.enc());
    }

    pub fn to32(self: Register) Register {
        return @intToEnum(Register, @as(u8, self.enc()) + 16);
    }

    pub fn to16(self: Register) Register {
        return @intToEnum(Register, @as(u8, self.enc()) + 32);
    }

    pub fn to8(self: Register) Register {
        return @intToEnum(Register, @as(u8, self.enc()) + 48);
    }

    pub fn fmtPrint(self: Register, writer: anytype) !void {
        try writer.writeAll(@tagName(self));
    }
};

pub const Memory = struct {
    size: Size,
    scale_index: ?ScaleIndex = null,
    base: union(enum) {
        reg: Register,
        rip: void,
        seg: void, // TODO
    },
    disp: ?u32 = null,

    pub const ScaleIndex = packed struct {
        scale: u2,
        index: Register,
    };

    pub const Size = enum(u2) {
        byte = 0b00,
        word = 0b01,
        dword = 0b10,
        qword = 0b11,

        fn fromBitSize(bit_size: u64) Size {
            return @intToEnum(Size, math.log2_int(u4, @intCast(u4, @divExact(bit_size, 8))));
        }

        fn bitSize(s: Size) u64 {
            return 8 * (math.powi(u8, 2, @enumToInt(s)) catch unreachable);
        }
    };

    pub fn fmtPrint(self: Memory, writer: anytype) !void {
        assert(self.scale_index == null); // TODO handle SIB

        switch (self.size) {
            .byte => try writer.writeAll("byte ptr "),
            .word => try writer.writeAll("word ptr "),
            .dword => try writer.writeAll("dword ptr "),
            .qword => try writer.writeAll("qword ptr "),
        }

        try writer.writeByte('[');

        switch (self.base) {
            .reg => |r| try r.fmtPrint(writer),
            .rip => try writer.writeAll("rip"),
            .seg => unreachable, // TODO handle segment registers
        }

        if (self.disp) |disp| {
            const disp_signed: i32 = @bitCast(i32, disp);
            const disp_abs: u32 = @intCast(u32, try std.math.absInt(disp_signed));
            if (sign(disp_signed) < 0) {
                try writer.writeAll(" - ");
            } else {
                try writer.writeAll(" + ");
            }
            switch (self.size) {
                .byte => try writer.print("0x{x}", .{@intCast(u8, disp_abs)}),
                else => try writer.print("0x{x}", .{disp_abs}),
            }
        }

        try writer.writeByte(']');
    }

    pub fn size_(self: Memory) u7 {
        return @intCast(u7, self.size.bitSize());
    }

    pub fn encode(self: Memory, operand: u3, encoder: anytype) !void {
        switch (self.base) {
            .reg => |reg| {
                const dst = reg.lowEnc();
                const src = operand;
                if (dst == 4 or self.scale_index != null) {
                    if (self.disp == null and dst != 5) {
                        try encoder.modRm_SIBDisp0(src);
                        if (self.scale_index) |si| {
                            try encoder.sib_scaleIndexBase(si.scale, si.index.lowEnc(), dst);
                        } else {
                            try encoder.sib_base(dst);
                        }
                    } else {
                        const disp = self.disp orelse 0;
                        if (immOpSize(disp) == 8) {
                            try encoder.modRm_SIBDisp8(src);
                            if (self.scale_index) |si| {
                                try encoder.sib_scaleIndexBaseDisp8(si.scale, si.index.lowEnc(), dst);
                            } else {
                                try encoder.sib_baseDisp8(dst);
                            }
                            try encoder.disp8(@bitCast(i8, @truncate(u8, disp)));
                        } else {
                            try encoder.modRm_SIBDisp32(src);
                            if (self.scale_index) |si| {
                                try encoder.sib_scaleIndexBaseDisp32(si.scale, si.index.lowEnc(), dst);
                            } else {
                                try encoder.sib_baseDisp32(dst);
                            }
                            try encoder.disp32(@bitCast(i32, disp));
                        }
                    }
                } else {
                    if (self.disp == null and dst != 5) {
                        try encoder.modRm_indirectDisp0(src, dst);
                    } else {
                        const disp = self.disp orelse 0;
                        if (immOpSize(disp) == 8) {
                            try encoder.modRm_indirectDisp8(src, dst);
                            try encoder.disp8(@bitCast(i8, @truncate(u8, disp)));
                        } else {
                            try encoder.modRm_indirectDisp32(src, dst);
                            try encoder.disp32(@bitCast(i32, disp));
                        }
                    }
                }
            },
            .rip => {
                try encoder.modRm_RIPDisp32(operand);
                try encoder.disp32(@bitCast(i32, self.disp orelse @as(u32, 0)));
            },
            .seg => {
                try encoder.modRm_SIBDisp0(operand);
                if (self.scale_index) |si| {
                    try encoder.sib_scaleIndexDisp32(si.scale, si.index.lowEnc());
                } else {
                    try encoder.sib_disp32();
                }
                try encoder.disp32(@bitCast(i32, self.disp orelse @as(u32, 0)));
            },
        }
    }
};

pub const RegisterOrMemory = union(enum) {
    reg: Register,
    mem: Memory,

    pub fn reg(register: Register) RegisterOrMemory {
        return .{ .reg = register };
    }

    pub fn mem(memory: Memory) RegisterOrMemory {
        return .{ .mem = memory };
    }

    pub fn fmtPrint(self: RegisterOrMemory, writer: anytype) !void {
        switch (self) {
            .reg => |r| try r.fmtPrint(writer),
            .mem => |m| try m.fmtPrint(writer),
        }
    }

    pub fn size(self: RegisterOrMemory) u7 {
        return switch (self) {
            .reg => |r| r.size(),
            .mem => |m| m.size_(), // TODO naming
        };
    }
};

pub const Instruction = struct {
    tag: Tag,
    enc: Enc,
    data: Data,

    pub const Tag = enum {
        add,
        cmp,
        mov,
        lea,

        fn encode(tag: Tag, enc: Enc, size: u7, encoder: anytype) !void {
            if (size == 8) switch (tag) {
                .add => unreachable, // TODO
                .cmp => switch (enc) {
                    .oi => unreachable, // does not support this encoding
                    .rm => try encoder.opcode_1byte(0x3a),
                    .mr => try encoder.opcode_1byte(0x38),
                    .mi => try encoder.opcode_1byte(0x80),
                },
                .mov => switch (enc) {
                    .oi => try encoder.opcode_1byte(0xb0),
                    .rm => try encoder.opcode_1byte(0x8a),
                    .mr => try encoder.opcode_1byte(0x88),
                    .mi => try encoder.opcode_1byte(0xc6),
                },
                .lea => unreachable, // does not support 8bit sizes
            } else switch (tag) {
                .add => unreachable, // TODO
                .cmp => switch (enc) {
                    .oi => unreachable, // does not support this encoding
                    .rm => try encoder.opcode_1byte(0x3b),
                    .mr => try encoder.opcode_1byte(0x39),
                    .mi => try encoder.opcode_1byte(0x81),
                },
                .mov => switch (enc) {
                    .oi => try encoder.opcode_1byte(0xb8),
                    .rm => try encoder.opcode_1byte(0x8b),
                    .mr => try encoder.opcode_1byte(0x89),
                    .mi => try encoder.opcode_1byte(0xc7),
                },
                .lea => switch (enc) {
                    .rm => try encoder.opcode_1byte(0x8d),
                    else => unreachable, // does not support different encodings
                },
            }
        }
    };

    pub const Enc = enum {
        oi,
        mi,
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

        pub fn mi(reg_or_mem: RegisterOrMemory, imm: u32) Data {
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
        imm: u32,
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
            .oi => unreachable, // TODO
            .rm => {
                const rm = self.data.rm;
                const dst_reg = rm.reg;
                if (dst_reg.size() == 16) {
                    try encoder.prefix16BitMode();
                }
                switch (rm.reg_or_mem) {
                    .reg => |src_reg| {
                        try encoder.rex(.{
                            .w = setRexWRegister(dst_reg) or setRexWRegister(src_reg),
                            .r = dst_reg.isExtended(),
                            .b = src_reg.isExtended(),
                        });
                        try self.tag.encode(.rm, dst_reg.size(), encoder);
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
                        try self.tag.encode(.rm, dst_reg.size(), encoder);
                        try src_mem.encode(dst_reg.lowEnc(), encoder);
                    },
                }
            },
            .mr => unreachable, // TODO
            .mi => {
                const mi = self.data.mi;
                const modrm_ext: u3 = switch (self.tag) {
                    .add => 0,
                    .cmp => 7,
                    .mov => 0,
                    else => unreachable,
                };
                switch (mi.reg_or_mem) {
                    .reg => |dst_reg| {
                        if (dst_reg.size() == 16) {
                            try encoder.prefix16BitMode();
                        }
                        try encoder.rex(.{
                            .w = setRexWRegister(dst_reg),
                            .b = dst_reg.isExtended(),
                        });
                        try self.tag.encode(.mi, dst_reg.size(), encoder);
                        try encoder.modRm_direct(modrm_ext, dst_reg.lowEnc());
                    },
                    .mem => |dst_mem| {
                        if (dst_mem.size == .word) {
                            try encoder.prefix16BitMode();
                        }
                        switch (dst_mem.base) {
                            .reg => |reg| {
                                try encoder.rex(.{
                                    .w = dst_mem.size == .qword,
                                    .b = reg.isExtended(),
                                });
                            },
                            .rip, .seg => {
                                try encoder.rex(.{
                                    .w = dst_mem.size == .qword,
                                });
                            },
                        }
                        try self.tag.encode(.mi, dst_mem.size_(), encoder);
                        try dst_mem.encode(modrm_ext, encoder);
                    },
                }
                try encodeImm(mi.imm, mi.reg_or_mem.size(), encoder);
            },
        }
    }

    pub fn fmtPrint(self: Instruction, writer: anytype) !void {
        switch (self.tag) {
            .add => try writer.writeAll("add "),
            .cmp => try writer.writeAll("cmp "),
            .mov => blk: {
                switch (self.enc) {
                    .oi => {
                        if (self.data.oi.reg.size() == 64) {
                            break :blk try writer.writeAll("movabs ");
                        }
                    },
                    else => {},
                }
                try writer.writeAll("mov ");
            },
            .lea => try writer.writeAll("lea "),
        }

        switch (self.enc) {
            .oi => {
                const oi = self.data.oi;
                try oi.reg.fmtPrint(writer);
                try writer.writeAll(", ");

                if (oi.reg.size() == 64) {
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
            .mi => {
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
    if (reg.size() > 64) return false;
    if (reg.size() == 64) return true;
    return switch (reg) {
        .ah, .ch, .dh, .bh => true,
        else => false,
    };
}

inline fn immOpSize(u_imm: u32) u6 {
    const imm = @bitCast(i32, u_imm);
    if (math.minInt(i8) <= imm and imm <= math.maxInt(i8)) {
        return 8;
    }
    if (math.minInt(i16) <= imm and imm <= math.maxInt(i16)) {
        return 16;
    }
    return 32;
}

fn encodeImm(imm: u32, size: u7, encoder: anytype) !void {
    switch (size) {
        8 => try encoder.imm8(@bitCast(i8, @truncate(u8, imm))),
        16 => try encoder.imm16(@bitCast(i16, @truncate(u16, imm))),
        32, 64 => try encoder.imm32(@bitCast(i32, imm)),
        else => unreachable,
    }
}

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

    fn size(self: ParsedOpc, rex: Rex) u7 {
        if (self.is_byte_sized) return 8;
        if (rex.w) return 64;
        // TODO handle legacy prefixes such as 0x66.
        return 32;
    }
};

fn parseImm(reader: anytype, size: u7) !u32 {
    const imm: u32 = switch (size) {
        8 => @bitCast(u32, @intCast(i32, try reader.readInt(i8, .Little))),
        16 => @bitCast(u32, @intCast(i32, try reader.readInt(i16, .Little))),
        32, 64 => @bitCast(u32, try reader.readInt(i32, .Little)),
        else => unreachable,
    };
    return imm;
}

const Rex = struct {
    w: bool = false,
    r: bool = false,
    x: bool = false,
    b: bool = false,

    fn isValid(byte: u8) bool {
        const mask: u8 = 0b0100_0000;
        return mask & byte != 0;
    }

    fn parse(byte: u8) ?Rex {
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
        const size = opc.size(rex);

        const data: Instruction.Data = data: {
            switch (opc.enc) {
                .oi => {
                    if (rex.r or rex.x) return error.InvalidRexForEncoding;
                    const reg = Register.fromLowEnc(opc.extra, rex.b, size);
                    const imm: u64 = switch (size) {
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
                            const reg = Register.fromLowEnc(op2, rex.r, size);
                            const imm = try parseImm(reader, size);
                            break :data Instruction.Data.mi(RegisterOrMemory.reg(reg), imm);
                        },
                        0b01 => {
                            // indirect addressing with an 8bit displacement
                            if (op2 == 0b100) {
                                // TODO handle SIB byte addressing
                                return error.Todo;
                            }

                            const reg = Register.fromLowEnc(op2, rex.b, 64);
                            const disp: u32 = @bitCast(u32, @intCast(i32, try reader.readInt(i8, .Little)));
                            const imm = try parseImm(reader, size);
                            break :data Instruction.Data.mi(RegisterOrMemory.mem(.{
                                .size = Memory.Size.fromBitSize(size),
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
                            const disp: u32 = @bitCast(u32, try reader.readInt(i32, .Little));
                            const imm = try parseImm(reader, size);
                            break :data Instruction.Data.mi(RegisterOrMemory.mem(.{
                                .size = Memory.Size.fromBitSize(size),
                                .base = .{ .reg = reg },
                                .disp = disp,
                            }), imm);
                        },
                        0b00 => {
                            // indirect addressing
                            if (op2 == 0b101) {
                                // RIP with 32bit displacement
                                const disp: u32 = @bitCast(u32, try reader.readInt(i32, .Little));
                                const imm = try parseImm(reader, size);
                                break :data Instruction.Data.mi(RegisterOrMemory.mem(.{
                                    .size = Memory.Size.fromBitSize(size),
                                    .base = .rip,
                                    .disp = disp,
                                }), imm);
                            }

                            if (op2 == 0b100) {
                                // TODO SIB with disp 0bit
                                return error.Todo;
                            }

                            const reg = Register.fromLowEnc(op2, rex.b, 64);
                            const imm = try parseImm(reader, size);
                            break :data Instruction.Data.mi(RegisterOrMemory.mem(.{
                                .size = Memory.Size.fromBitSize(size),
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
                            const reg1 = Register.fromLowEnc(op1, rex.r, size);
                            const reg2 = Register.fromLowEnc(op2, rex.b, size);
                            break :data Instruction.Data.rm(reg1, RegisterOrMemory.reg(reg2));
                        },
                        0b01 => {
                            // indirect addressing with an 8bit displacement
                            if (op2 == 0b100) {
                                // TODO handle SIB byte addressing
                                return error.Todo;
                            }

                            const reg1 = Register.fromLowEnc(op1, rex.r, size);
                            const reg2 = Register.fromLowEnc(op2, rex.b, 64);
                            const disp: u32 = @bitCast(u32, @intCast(i32, try reader.readInt(i8, .Little)));
                            break :data Instruction.Data.rm(reg1, RegisterOrMemory.mem(.{
                                .size = Memory.Size.fromBitSize(size),
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

                            const reg1 = Register.fromLowEnc(op1, rex.r, size);
                            const reg2 = Register.fromLowEnc(op2, rex.b, 64);
                            const disp: u32 = @bitCast(u32, try reader.readInt(i32, .Little));
                            break :data Instruction.Data.rm(reg1, RegisterOrMemory.mem(.{
                                .size = Memory.Size.fromBitSize(size),
                                .base = .{ .reg = reg2 },
                                .disp = disp,
                            }));
                        },
                        0b00 => {
                            // indirect addressing
                            if (op2 == 0b101) {
                                // RIP with 32bit displacement
                                const reg1 = Register.fromLowEnc(op1, rex.r, size);
                                const disp: u32 = @bitCast(u32, try reader.readInt(i32, .Little));
                                break :data Instruction.Data.rm(reg1, RegisterOrMemory.mem(.{
                                    .size = Memory.Size.fromBitSize(size),
                                    .base = .rip,
                                    .disp = disp,
                                }));
                            }

                            if (op2 == 0b100) {
                                // TODO SIB with disp 0bit
                                return error.Todo;
                            }

                            const reg1 = Register.fromLowEnc(op1, rex.r, size);
                            const reg2 = Register.fromLowEnc(op2, rex.b, 64);
                            break :data Instruction.Data.rm(reg1, RegisterOrMemory.mem(.{
                                .size = Memory.Size.fromBitSize(size),
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
                            const reg1 = Register.fromLowEnc(op1, rex.b, size);
                            const reg2 = Register.fromLowEnc(op2, rex.r, size);
                            break :data Instruction.Data.mr(RegisterOrMemory.reg(reg1), reg2);
                        },
                        0b01 => {
                            // indirect addressing with an 8bit displacement
                            if (op2 == 0b100) {
                                // TODO handle SIB byte addressing
                                return error.Todo;
                            }

                            const reg1 = Register.fromLowEnc(op1, rex.b, 64);
                            const reg2 = Register.fromLowEnc(op2, rex.r, size);
                            const disp: u32 = @bitCast(u32, @intCast(i32, try reader.readInt(i8, .Little)));
                            break :data Instruction.Data.mr(RegisterOrMemory.mem(.{
                                .size = Memory.Size.fromBitSize(size),
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
                            const reg2 = Register.fromLowEnc(op2, rex.r, size);
                            const disp: u32 = @bitCast(u32, try reader.readInt(i32, .Little));
                            break :data Instruction.Data.mr(RegisterOrMemory.mem(.{
                                .size = Memory.Size.fromBitSize(size),
                                .base = .{ .reg = reg1 },
                                .disp = disp,
                            }), reg2);
                        },
                        0b00 => {
                            // indirect addressing
                            if (op2 == 0b101) {
                                // RIP with 32bit displacement
                                const reg1 = Register.fromLowEnc(op1, rex.b, size);
                                const disp: u32 = @bitCast(u32, try reader.readInt(i32, .Little));
                                break :data Instruction.Data.mr(RegisterOrMemory.mem(.{
                                    .size = Memory.Size.fromBitSize(size),
                                    .base = .rip,
                                    .disp = disp,
                                }), reg1);
                            }

                            if (op2 == 0b100) {
                                // TODO SIB with disp 0bit
                                return error.Todo;
                            }

                            const reg1 = Register.fromLowEnc(op1, rex.b, 64);
                            const reg2 = Register.fromLowEnc(op2, rex.r, size);
                            break :data Instruction.Data.mr(RegisterOrMemory.mem(.{
                                .size = Memory.Size.fromBitSize(size),
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

pub fn Encoder(comptime T: type) type {
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

inline fn sign(i: anytype) @TypeOf(i) {
    return @as(@TypeOf(i), @boolToInt(i > 0)) - @boolToInt(i < 0);
}

test "disassemble" {
    var disassembler = Disassembler.init(&.{
        // zig fmt: off
        0x40, 0xb7, 0x10,                                           // mov dil, 0x10
        0x49, 0xbc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, // mov r12, 0x1000000000000000
        0xb8, 0x00, 0x00, 0x00, 0x10,                               // mov eax, 0x10000000 
        0x48, 0x8b, 0xd8,                                           // mov rbx, rax
        0x4d, 0x8b, 0xdc,                                           // mov r11, r12
        0x49, 0x8b, 0xd4,                                           // mov rdx, r12
        0x4d, 0x89, 0xdc,                                           // mov r12, r11
        0x49, 0x89, 0xd4,                                           // mov r12, rdx
        0x4c, 0x8b, 0x65, 0xf0,                                     // mov r12, qword ptr [rbp - 0x10] 
        0x48, 0x8b, 0x85, 0x00, 0xf0, 0xff, 0xff,                   // mov rax, qword ptr [rbp - 0x1000]
        0x48, 0x8b, 0x1d, 0x00, 0x00, 0x00, 0x00,                   // mov rbx, qword ptr [rip + 0x0]
        0x48, 0x8b, 0x18,                                           // mov rbx, qword ptr [rax]
        // zig fmt: on
    });

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .oi);
        try testing.expect(inst.data.oi.reg == .bh);
        try testing.expect(inst.data.oi.imm == 0x10);
    }

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .oi);
        try testing.expect(inst.data.oi.reg == .r12);
        try testing.expect(inst.data.oi.imm == 0x1000000000000000);
    }

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .oi);
        try testing.expect(inst.data.oi.reg == .eax);
        try testing.expect(inst.data.oi.imm == 0x10000000);
    }

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .rm);
        try testing.expect(inst.data.rm.reg == .rbx);
        try testing.expect(inst.data.rm.reg_or_mem.reg == .rax);
    }

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .rm);
        try testing.expect(inst.data.rm.reg == .r11);
        try testing.expect(inst.data.rm.reg_or_mem.reg == .r12);
    }

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .rm);
        try testing.expect(inst.data.rm.reg == .rdx);
        try testing.expect(inst.data.rm.reg_or_mem.reg == .r12);
    }

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .mr);
        try testing.expect(inst.data.mr.reg_or_mem.reg == .r12);
        try testing.expect(inst.data.mr.reg == .r11);
    }

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .mr);
        try testing.expect(inst.data.mr.reg_or_mem.reg == .r12);
        try testing.expect(inst.data.mr.reg == .rdx);
    }

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .rm);
        try testing.expect(inst.data.rm.reg == .r12);
        try testing.expect(inst.data.rm.reg_or_mem.mem.size == .qword);
        try testing.expect(inst.data.rm.reg_or_mem.mem.scale_index == null);
        try testing.expect(inst.data.rm.reg_or_mem.mem.base.reg == .rbp);
        try testing.expect(@intCast(i8, @bitCast(i32, inst.data.rm.reg_or_mem.mem.disp.?)) == -0x10);
    }

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .rm);
        try testing.expect(inst.data.rm.reg == .rax);
        try testing.expect(inst.data.rm.reg_or_mem.mem.size == .qword);
        try testing.expect(inst.data.rm.reg_or_mem.mem.scale_index == null);
        try testing.expect(inst.data.rm.reg_or_mem.mem.base.reg == .rbp);
        try testing.expect(@bitCast(i32, inst.data.rm.reg_or_mem.mem.disp.?) == -0x1000);
    }

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .rm);
        try testing.expect(inst.data.rm.reg == .rbx);
        try testing.expect(inst.data.rm.reg_or_mem.mem.size == .qword);
        try testing.expect(inst.data.rm.reg_or_mem.mem.scale_index == null);
        try testing.expect(inst.data.rm.reg_or_mem.mem.base == .rip);
        try testing.expect(@bitCast(i32, inst.data.rm.reg_or_mem.mem.disp.?) == 0x0);
    }

    {
        const inst = (try disassembler.next()).?;
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .rm);
        try testing.expect(inst.data.rm.reg == .rbx);
        try testing.expect(inst.data.rm.reg_or_mem.mem.size == .qword);
        try testing.expect(inst.data.rm.reg_or_mem.mem.scale_index == null);
        try testing.expect(inst.data.rm.reg_or_mem.mem.base.reg == .rax);
        try testing.expect(inst.data.rm.reg_or_mem.mem.disp == null);
    }
}

test "disassemble - mnemonic" {
    const gpa = testing.allocator;
    var disassembler = Disassembler.init(&.{
        // zig fmt: off
        0x48, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x41, 0xbc, 0xf0, 0xff, 0xff, 0xff,
        0x4c, 0x8b, 0x65, 0xf0,
        0x48, 0x8b, 0x85, 0x00, 0xf0, 0xff, 0xff,
        0x48, 0x8b, 0x18,
        0xc6, 0x45, 0xf0, 0x10,
        0x49, 0xc7, 0x43, 0xf0, 0x10, 0x00, 0x00, 0x00,
        0x49, 0x89, 0x43, 0xf0,
        0x48, 0x8d, 0x45, 0xf0,
        0x41, 0x8d, 0x43, 0x10,
        0x4c, 0x8d, 0x25, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x03, 0x05, 0x00, 0x00, 0x00, 0x00,
        // zig fmt: on
    });

    var buf = std.ArrayList(u8).init(gpa);
    defer buf.deinit();

    while (try disassembler.next()) |inst| {
        try inst.fmtPrint(buf.writer());
        try buf.append('\n');
    }

    try testing.expectEqualStrings(
        \\movabs rax, 0x10
        \\mov r12d, -0x10
        \\mov r12, qword ptr [rbp - 0x10]
        \\mov rax, qword ptr [rbp - 0x1000]
        \\mov rbx, qword ptr [rax]
        \\mov byte ptr [rbp - 0x10], 0x10
        \\mov qword ptr [r11 - 0x10], 0x10
        \\mov qword ptr [r11 - 0x10], rax
        \\lea rax, qword ptr [rbp - 0x10]
        \\lea eax, dword ptr [r11 + 0x10]
        \\lea r12, qword ptr [rip + 0x0]
        \\add rax, qword ptr [rip + 0x0]
        \\
    , buf.items);
}

test "encode" {
    var buf = std.ArrayList(u8).init(testing.allocator);
    defer buf.deinit();

    const inst = Instruction{
        .tag = .mov,
        .enc = .mi,
        .data = Instruction.Data.mi(RegisterOrMemory.reg(.rbx), 0x4),
    };
    try inst.encode(buf.writer());
    try testing.expectEqualSlices(u8, &.{0x48,0xc7,0xc3,0x4,0x0,0x0,0x0}, buf.items);
}
