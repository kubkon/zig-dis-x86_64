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

    pub fn fromLowEnc(low_enc: u3, is_extended: bool) Register {
        const reg_id: u4 = @intCast(u4, @boolToInt(is_extended)) << 3 | low_enc;
        return @intToEnum(Register, reg_id);
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
        ds: void, // TODO
    },
    disp: u32,

    pub const ScaleIndex = packed struct {
        scale: u2,
        index: Register,
    };

    pub const Size = enum(u2) {
        byte = 0b00,
        word = 0b01,
        dword = 0b10,
        qword = 0b11,

        fn new(bit_size: u64) Size {
            return @intToEnum(Size, math.log2_int(u4, @intCast(u4, @divExact(bit_size, 8))));
        }

        fn sizeInBits(s: Size) u64 {
            return 8 * (math.powi(u8, 2, @enumToInt(s)) catch unreachable);
        }
    };

    fn fmtPrint(self: Memory, writer: anytype) !void {
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
            .ds => unreachable, // TODO handle segment registers
        }

        if (self.disp > 0) {
            const disp_signed: i32 = @bitCast(i32, self.disp);
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

    fn fmtPrint(self: RegisterOrMemory, writer: anytype) !void {
        switch (self) {
            .reg => |r| try r.fmtPrint(writer),
            .mem => |m| try m.fmtPrint(writer),
        }
    }
};

pub const Instruction = struct {
    tag: Tag,
    enc: Enc,
    data: union {
        oi: Oi,
        mr: Mr,
        rm: Rm,
    },

    pub const Tag = enum {
        mov,
    };

    pub const Enc = enum {
        oi,
        mr,
        rm,
    };

    pub const Oi = struct {
        reg: Register,
        imm: u64,
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

    fn new(tag: Instruction.Tag, enc: Instruction.Enc, is_byte_sized: bool, reg: u3) ParsedOpc {
        return .{
            .tag = tag,
            .enc = enc,
            .is_byte_sized = is_byte_sized,
            .reg = reg,
        };
    }
};

fn parseOpcode(reader: anytype) Error!ParsedOpc {
    const next_byte = try reader.readByte();
    switch (next_byte) {
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
        0xc6 => return error.Todo,
        0xc7 => return error.Todo,
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
        const mask: u8 = 0b0100_0000;
        const masked = byte & mask;

        if (masked == 0) return null;

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
    InputTooShort,
    InvalidRexForEncoding,
    Todo,
};

pub fn disassembleSingle(code: []const u8) Error!Instruction {
    if (code.len == 0) return error.InputTooShort;

    var stream = std.io.fixedBufferStream(code);
    const reader = stream.reader();

    // TODO parse legacy prefixes such as 0x66, etc.
    const rex = Rex.parse(try reader.readByte());
    if (rex == null) {
        try stream.seekBy(-1);
    }
    const opc = try parseOpcode(reader);

    switch (opc.enc) {
        .oi => {
            var is_extended: bool = false;
            var is_wide: bool = false;
            if (rex) |r| {
                if (r.r or r.x) return error.InvalidRexForEncoding;
                is_extended = r.b;
                is_wide = r.w;
            }
            const reg_unsized = Register.fromLowEnc(opc.reg, is_extended);
            const reg: Register = reg: {
                if (opc.is_byte_sized) break :reg reg_unsized.to8();
                if (is_wide) break :reg reg_unsized.to64();
                break :reg reg_unsized.to32();
            };
            const imm: u64 = imm: {
                if (opc.is_byte_sized) break :imm @bitCast(u64, @intCast(i64, try reader.readInt(i8, .Little)));
                if (is_wide) break :imm try reader.readInt(u64, .Little);
                break :imm @bitCast(u64, @intCast(i64, try reader.readInt(i32, .Little)));
            };

            return Instruction{
                .tag = opc.tag,
                .enc = opc.enc,
                .data = .{
                    .oi = .{
                        .reg = reg,
                        .imm = imm,
                    },
                },
            };
        },
        .rm => {
            const is_wide: bool = if (rex) |r| r.w else false;
            const modrm_byte = try reader.readByte();
            const mod: u2 = @truncate(u2, modrm_byte >> 6);
            const op1: u3 = @truncate(u3, modrm_byte >> 3);
            const op2: u3 = @truncate(u3, modrm_byte);

            switch (mod) {
                0b11 => {
                    // direct addressing
                    const reg1_unsized = Register.fromLowEnc(op1, if (rex) |r| r.r else false);
                    const reg1: Register = reg: {
                        if (opc.is_byte_sized) break :reg reg1_unsized.to8();
                        if (is_wide) break :reg reg1_unsized.to64();
                        break :reg reg1_unsized.to32();
                    };
                    const reg2_unsized = Register.fromLowEnc(op2, if (rex) |r| r.b else false);
                    const reg2: Register = reg: {
                        if (opc.is_byte_sized) break :reg reg2_unsized.to8();
                        if (is_wide) break :reg reg2_unsized.to64();
                        break :reg reg2_unsized.to32();
                    };
                    return Instruction{
                        .tag = opc.tag,
                        .enc = opc.enc,
                        .data = .{
                            .rm = .{
                                .reg = reg1,
                                .reg_or_mem = .{ .reg = reg2 },
                            },
                        },
                    };
                },
                0b01 => {
                    // indirect addressing with an 8bit displacement
                    if (op2 == 0b100) {
                        // TODO handle SIB byte addressing
                        return error.Todo;
                    }

                    const reg1_unsized = Register.fromLowEnc(op1, if (rex) |r| r.r else false);
                    const reg1: Register = reg: {
                        if (opc.is_byte_sized) break :reg reg1_unsized.to8();
                        if (is_wide) break :reg reg1_unsized.to64();
                        break :reg reg1_unsized.to32();
                    };
                    const reg2_unsized = Register.fromLowEnc(op2, if (rex) |r| r.b else false);
                    const reg2: Register = reg2_unsized.to64();
                    const size: Memory.Size = size: {
                        if (opc.is_byte_sized) break :size .byte;
                        if (is_wide) break :size .qword;
                        break :size .dword;
                    };
                    const disp: u32 = @bitCast(u32, @intCast(i32, try reader.readInt(i8, .Little)));
                    const mem = Memory{
                        .size = size,
                        .base = .{ .reg = reg2 },
                        .disp = disp,
                    };

                    return Instruction{
                        .tag = opc.tag,
                        .enc = opc.enc,
                        .data = .{
                            .rm = .{
                                .reg = reg1,
                                .reg_or_mem = .{ .mem = mem },
                            },
                        },
                    };
                },
                0b10 => {
                    // indirect addressing with a 32bit displacement
                    if (op2 == 0b100) {
                        // TODO handle SIB byte addressing
                        return error.Todo;
                    }

                    const reg1_unsized = Register.fromLowEnc(op1, if (rex) |r| r.r else false);
                    const reg1: Register = reg: {
                        if (opc.is_byte_sized) break :reg reg1_unsized.to8();
                        if (is_wide) break :reg reg1_unsized.to64();
                        break :reg reg1_unsized.to32();
                    };
                    const reg2_unsized = Register.fromLowEnc(op2, if (rex) |r| r.b else false);
                    const reg2: Register = reg2_unsized.to64();
                    const size: Memory.Size = size: {
                        if (opc.is_byte_sized) break :size .byte;
                        if (is_wide) break :size .qword;
                        break :size .dword;
                    };
                    const disp: u32 = @bitCast(u32, try reader.readInt(i32, .Little));
                    const mem = Memory{
                        .size = size,
                        .base = .{ .reg = reg2 },
                        .disp = disp,
                    };

                    return Instruction{
                        .tag = opc.tag,
                        .enc = opc.enc,
                        .data = .{
                            .rm = .{
                                .reg = reg1,
                                .reg_or_mem = .{ .mem = mem },
                            },
                        },
                    };
                },
                0b00 => {
                    // indirect addressing
                    if (op2 == 0b101) {
                        // RIP with 32bit displacement
                        const reg1_unsized = Register.fromLowEnc(op1, if (rex) |r| r.r else false);
                        const reg1: Register = reg: {
                            if (opc.is_byte_sized) break :reg reg1_unsized.to8();
                            if (is_wide) break :reg reg1_unsized.to64();
                            break :reg reg1_unsized.to32();
                        };
                        const size: Memory.Size = size: {
                            if (opc.is_byte_sized) break :size .byte;
                            if (is_wide) break :size .qword;
                            break :size .dword;
                        };
                        const disp: u32 = @bitCast(u32, try reader.readInt(i32, .Little));
                        const mem = Memory{
                            .size = size,
                            .base = .rip,
                            .disp = disp,
                        };

                        return Instruction{
                            .tag = opc.tag,
                            .enc = opc.enc,
                            .data = .{
                                .rm = .{
                                    .reg = reg1,
                                    .reg_or_mem = .{ .mem = mem },
                                },
                            },
                        };
                    }
                    if (op2 == 0b100) {
                        // TODO SIB with disp 0bit
                        return error.Todo;
                    }

                    const reg1_unsized = Register.fromLowEnc(op1, if (rex) |r| r.r else false);
                    const reg1: Register = reg: {
                        if (opc.is_byte_sized) break :reg reg1_unsized.to8();
                        if (is_wide) break :reg reg1_unsized.to64();
                        break :reg reg1_unsized.to32();
                    };
                    const reg2_unsized = Register.fromLowEnc(op2, if (rex) |r| r.b else false);
                    const reg2: Register = reg2_unsized.to64();
                    const size: Memory.Size = size: {
                        if (opc.is_byte_sized) break :size .byte;
                        if (is_wide) break :size .qword;
                        break :size .dword;
                    };
                    const mem = Memory{
                        .size = size,
                        .base = .{ .reg = reg2 },
                        .disp = 0,
                    };

                    return Instruction{
                        .tag = opc.tag,
                        .enc = opc.enc,
                        .data = .{
                            .rm = .{
                                .reg = reg1,
                                .reg_or_mem = .{ .mem = mem },
                            },
                        },
                    };
                },
            }
        },
        .mr => {
            const is_wide: bool = if (rex) |r| r.w else false;
            const modrm_byte = try reader.readByte();
            const mod: u2 = @truncate(u2, modrm_byte >> 6);
            const op2: u3 = @truncate(u3, modrm_byte >> 3);
            const op1: u3 = @truncate(u3, modrm_byte);

            switch (mod) {
                0b11 => {
                    // direct addressing
                    const reg1_unsized = Register.fromLowEnc(op1, if (rex) |r| r.b else false);
                    const reg1: Register = reg: {
                        if (opc.is_byte_sized) break :reg reg1_unsized.to8();
                        if (is_wide) break :reg reg1_unsized.to64();
                        break :reg reg1_unsized.to32();
                    };
                    const reg2_unsized = Register.fromLowEnc(op2, if (rex) |r| r.r else false);
                    const reg2: Register = reg: {
                        if (opc.is_byte_sized) break :reg reg2_unsized.to8();
                        if (is_wide) break :reg reg2_unsized.to64();
                        break :reg reg2_unsized.to32();
                    };
                    return Instruction{
                        .tag = opc.tag,
                        .enc = opc.enc,
                        .data = .{
                            .mr = .{
                                .reg_or_mem = .{ .reg = reg1 },
                                .reg = reg2,
                            },
                        },
                    };
                },
                else => return error.Todo,
            }
        },
    }
}

inline fn sign(i: anytype) @TypeOf(i) {
    return @as(@TypeOf(i), @boolToInt(i > 0)) - @boolToInt(i < 0);
}

test "disassemble" {
    {
        // mov dil, 0x10
        const inst = try disassembleSingle(&.{ 0x40, 0xb7, 0x10 });
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .oi);
        try testing.expect(inst.data.oi.reg == .bh);
        try testing.expect(inst.data.oi.imm == 0x10);
    }

    {
        // mov r12, 0x100000000000000
        const inst = try disassembleSingle(&.{ 0x49, 0xbc, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x10 });
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .oi);
        try testing.expect(inst.data.oi.reg == .r12);
        try testing.expect(inst.data.oi.imm == 0x1000000000000000);
    }

    {
        // mov eax, 0x10000000
        const inst = try disassembleSingle(&.{ 0xb8, 0x0, 0x0, 0x0, 0x10 });
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .oi);
        try testing.expect(inst.data.oi.reg == .eax);
        try testing.expect(inst.data.oi.imm == 0x10000000);
    }

    {
        // mov rbx, rax
        const inst = try disassembleSingle(&.{ 0x48, 0x8b, 0xd8 });
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .rm);
        try testing.expect(inst.data.rm.reg == .rbx);
        try testing.expect(inst.data.rm.reg_or_mem.reg == .rax);
    }

    {
        // mov r11, r12
        const inst = try disassembleSingle(&.{ 0x4d, 0x8b, 0xdc });
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .rm);
        try testing.expect(inst.data.rm.reg == .r11);
        try testing.expect(inst.data.rm.reg_or_mem.reg == .r12);
    }

    {
        // mov rdx, r12
        const inst = try disassembleSingle(&.{ 0x49, 0x8b, 0xd4 });
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .rm);
        try testing.expect(inst.data.rm.reg == .rdx);
        try testing.expect(inst.data.rm.reg_or_mem.reg == .r12);
    }

    {
        // mov r12, r11
        const inst = try disassembleSingle(&.{ 0x4d, 0x89, 0xdc });
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .mr);
        try testing.expect(inst.data.mr.reg_or_mem.reg == .r12);
        try testing.expect(inst.data.mr.reg == .r11);
    }

    {
        // mov r12, rdx
        const inst = try disassembleSingle(&.{ 0x49, 0x89, 0xd4 });
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .mr);
        try testing.expect(inst.data.mr.reg_or_mem.reg == .r12);
        try testing.expect(inst.data.mr.reg == .rdx);
    }

    {
        // mov r12, qword ptr [rbp - 0x10]
        const inst = try disassembleSingle(&.{ 0x4c, 0x8b, 0x65, 0xf0 });
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .rm);
        try testing.expect(inst.data.rm.reg == .r12);
        try testing.expect(inst.data.rm.reg_or_mem.mem.size == .qword);
        try testing.expect(inst.data.rm.reg_or_mem.mem.scale_index == null);
        try testing.expect(inst.data.rm.reg_or_mem.mem.base.reg == .rbp);
        try testing.expect(@intCast(i8, @bitCast(i32, inst.data.rm.reg_or_mem.mem.disp)) == -0x10);
    }

    {
        // mov rax, qword ptr [rbp - 0x1000]
        const inst = try disassembleSingle(&.{ 0x48, 0x8b, 0x85, 0x0, 0xf0, 0xff, 0xff });
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .rm);
        try testing.expect(inst.data.rm.reg == .rax);
        try testing.expect(inst.data.rm.reg_or_mem.mem.size == .qword);
        try testing.expect(inst.data.rm.reg_or_mem.mem.scale_index == null);
        try testing.expect(inst.data.rm.reg_or_mem.mem.base.reg == .rbp);
        try testing.expect(@bitCast(i32, inst.data.rm.reg_or_mem.mem.disp) == -0x1000);
    }

    {
        const inst = try disassembleSingle(&.{ 0x48, 0x8b, 0x1d, 0x0, 0x0, 0x0, 0x0 });
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .rm);
        try testing.expect(inst.data.rm.reg == .rbx);
        try testing.expect(inst.data.rm.reg_or_mem.mem.size == .qword);
        try testing.expect(inst.data.rm.reg_or_mem.mem.scale_index == null);
        try testing.expect(inst.data.rm.reg_or_mem.mem.base == .rip);
        try testing.expect(@bitCast(i32, inst.data.rm.reg_or_mem.mem.disp) == 0x0);
    }

    {
        const inst = try disassembleSingle(&.{ 0x48, 0x8b, 0x18 });
        try testing.expect(inst.tag == .mov);
        try testing.expect(inst.enc == .rm);
        try testing.expect(inst.data.rm.reg == .rbx);
        try testing.expect(inst.data.rm.reg_or_mem.mem.size == .qword);
        try testing.expect(inst.data.rm.reg_or_mem.mem.scale_index == null);
        try testing.expect(inst.data.rm.reg_or_mem.mem.base.reg == .rax);
        try testing.expect(@bitCast(i32, inst.data.rm.reg_or_mem.mem.disp) == 0);
    }
}

test "disassemble - mnemonic" {
    const gpa = testing.allocator;

    {
        // movabs rax, 0x10
        const inst = try disassembleSingle(&.{ 0x48, 0xb8, 0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 });
        var buf = std.ArrayList(u8).init(gpa);
        defer buf.deinit();
        try inst.fmtPrint(buf.writer());
        try testing.expectEqualStrings("movabs rax, 0x10", buf.items);
    }

    {
        // mov r12d, -0x10
        const inst = try disassembleSingle(&.{ 0x41, 0xbc, 0xf0, 0xff, 0xff, 0xff });
        var buf = std.ArrayList(u8).init(gpa);
        defer buf.deinit();
        try inst.fmtPrint(buf.writer());
        try testing.expectEqualStrings("mov r12d, -0x10", buf.items);
    }

    {
        // mov r12, qword ptr [rbp - 0x10]
        const inst = try disassembleSingle(&.{ 0x4c, 0x8b, 0x65, 0xf0 });
        var buf = std.ArrayList(u8).init(gpa);
        defer buf.deinit();
        try inst.fmtPrint(buf.writer());
        try testing.expectEqualStrings("mov r12, qword ptr [rbp - 0x10]", buf.items);
    }

    {
        // mov rax, qword ptr [rbp - 0x1000]
        const inst = try disassembleSingle(&.{ 0x48, 0x8b, 0x85, 0x0, 0xf0, 0xff, 0xff });
        var buf = std.ArrayList(u8).init(gpa);
        defer buf.deinit();
        try inst.fmtPrint(buf.writer());
        try testing.expectEqualStrings("mov rax, qword ptr [rbp - 0x1000]", buf.items);
    }

    {
        // mov rbx, qword ptr [rax]
        const inst = try disassembleSingle(&.{ 0x48, 0x8b, 0x18 });
        var buf = std.ArrayList(u8).init(gpa);
        defer buf.deinit();
        try inst.fmtPrint(buf.writer());
        try testing.expectEqualStrings("mov rbx, qword ptr [rax]", buf.items);
    }
}
