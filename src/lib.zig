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
        const as_str = switch (self) {
            // zig fmt: off
            .rax => "rax",
            .rbx => "rbx",
            .rcx => "rcx",
            .rdx => "rdx",
            .rsp => "rsp",
            .rbp => "rbp",
            .rsi => "rsi",
            .rdi => "rdi",
            .r8  => "r8",
            .r9  => "r9",
            .r10 => "r10",
            .r11 => "r11",
            .r12 => "r12",
            .r13 => "r13",
            .r14 => "r14",
            .r15 => "r15",

            .eax  => "eax",
            .ebx  => "ebx",
            .ecx  => "ecx",
            .edx  => "edx",
            .esp  => "esp",
            .ebp  => "ebp",
            .esi  => "esi",
            .edi  => "edi",
            .r8d  => "r8d",
            .r9d  => "r9d",
            .r10d => "r10d",
            .r11d => "r11d",
            .r12d => "r12d",
            .r13d => "r13d",
            .r14d => "r14d",
            .r15d => "r15d",

            .ax   => "ax",
            .bx   => "bx",
            .cx   => "cx",
            .dx   => "dx",
            .sp   => "sp",
            .bp   => "bp",
            .si   => "si",
            .di   => "di",
            .r8w  => "r8w",
            .r9w  => "r9w",
            .r10w => "r10w",
            .r11w => "r11w",
            .r12w => "r12w",
            .r13w => "r13w",
            .r14w => "r14w",
            .r15w => "r15w",

            .al   => "al",
            .bl   => "bl",
            .cl   => "cl",
            .dl   => "dl",
            .ah   => "ah",
            .bh   => "bh",
            .ch   => "ch",
            .dh   => "dh",
            .r8b  => "r8b",
            .r9b  => "r9b",
            .r10b => "r10b",
            .r11b => "r11b",
            .r12b => "r12b",
            .r13b => "r13b",
            .r14b => "r14b",
            .r15b => "r15b",
            // zig fmt: on
        };
        try writer.writeAll(as_str);
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
};

pub const Instruction = struct {
    tag: Tag,
    enc: Enc,
    data: Data,

    pub const Tag = enum {
        add,
        mov,
        lea,
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

    pub fn fmtPrint(self: Instruction, writer: anytype) !void {
        switch (self.tag) {
            .add => try writer.writeAll("add "),
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

const ParsedOpc = struct {
    tag: Instruction.Tag,
    enc: Instruction.Enc,
    is_byte_sized: bool,
    reg: u3,

    fn parse(reader: anytype) Error!ParsedOpc {
        const next_byte = try reader.readByte();
        switch (next_byte) {
            // add
            0x80 => return ParsedOpc.new(.add, .mi, true, 0),
            0x81 => return ParsedOpc.new(.add, .mi, false, 0),
            0x00 => return ParsedOpc.new(.add, .mr, true, 0),
            0x01 => return ParsedOpc.new(.add, .mr, false, 0),
            0x02 => return ParsedOpc.new(.add, .rm, true, 0),
            0x03 => return ParsedOpc.new(.add, .rm, false, 0),
            // mov
            0x88 => return ParsedOpc.new(.mov, .mr, true, 0),
            0x89 => return ParsedOpc.new(.mov, .mr, false, 0),
            0x8a => return ParsedOpc.new(.mov, .rm, true, 0),
            0x8b => return ParsedOpc.new(.mov, .rm, false, 0),
            0x8c => return ParsedOpc.new(.mov, .mr, false, 0),
            0x8e => return ParsedOpc.new(.mov, .rm, false, 0),
            0xa0 => return error.Todo,
            0xa1 => return error.Todo,
            0xa2 => return error.Todo,
            0xa3 => return error.Todo,
            0xc6 => return ParsedOpc.new(.mov, .mi, true, 0),
            0xc7 => return ParsedOpc.new(.mov, .mi, false, 0),
            // lea
            0x8d => return ParsedOpc.new(.lea, .rm, false, 0),
            // remaining
            else => {},
        }

        // check for OI encoding
        const mask: u8 = 0b1111_1000;
        switch (next_byte & mask) {
            // mov
            0xb0 => return ParsedOpc.new(.mov, .oi, true, @truncate(u3, next_byte)),
            0xb8 => return ParsedOpc.new(.mov, .oi, false, @truncate(u3, next_byte)),
            // remaining
            else => return error.Todo,
        }
    }

    fn new(tag: Instruction.Tag, enc: Instruction.Enc, is_byte_sized: bool, reg: u3) ParsedOpc {
        return .{
            .tag = tag,
            .enc = enc,
            .is_byte_sized = is_byte_sized,
            .reg = reg,
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
        const opc = try ParsedOpc.parse(reader);
        const size = opc.size(rex);

        const data: Instruction.Data = data: {
            switch (opc.enc) {
                .oi => {
                    if (rex.r or rex.x) return error.InvalidRexForEncoding;
                    const reg = Register.fromLowEnc(opc.reg, rex.b, size);
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

                    if (op1 != opc.reg) return error.InvalidModRmByte;

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
