const std = @import("std");
const math = std.math;
const testing = std.testing;

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
};

pub const RegisterOrMemory = union(enum) {
    reg: Register,
    mem: Memory,
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
                if (opc.is_byte_sized) break :imm try reader.readInt(u8, .Little);
                if (is_wide) break :imm try reader.readInt(u64, .Little);
                break :imm try reader.readInt(u32, .Little);
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
                else => return error.Todo,
            }
        },
        else => return error.Todo,
    }
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

    // {
    //     const inst = try disassembleSingle(&.{ 0x48, 0x8b, 0x1d, 0x0, 0x0, 0x0, 0x0 });
    //     std.log.warn("inst = {}", .{inst});
    // }
}
