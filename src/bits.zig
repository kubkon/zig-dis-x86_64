const std = @import("std");
const assert = std.debug.assert;
const math = std.math;

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

    pub fn fromLowEnc(low_enc: u3, is_extended: bool, bit_size: u7) Register {
        const reg_id: u4 = @intCast(u4, @boolToInt(is_extended)) << 3 | low_enc;
        const unsized = @intToEnum(Register, reg_id);
        return switch (bit_size) {
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

    pub fn bitSize(self: Register) u7 {
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
    ptr_size: PtrSize,
    scale_index: ?ScaleIndex = null,
    base: union(enum) {
        reg: Register,
        rip: void,
        seg: void, // TODO
    },
    disp: ?i32 = null,

    pub const ScaleIndex = packed struct {
        scale: u2,
        index: Register,
    };

    pub const PtrSize = enum(u2) {
        byte = 0b00,
        word = 0b01,
        dword = 0b10,
        qword = 0b11,

        pub fn fromBitSize(bit_size: u64) PtrSize {
            return @intToEnum(PtrSize, math.log2_int(u4, @intCast(u4, @divExact(bit_size, 8))));
        }

        pub fn bitSize(s: PtrSize) u64 {
            return 8 * (math.powi(u8, 2, @enumToInt(s)) catch unreachable);
        }
    };

    pub fn fmtPrint(self: Memory, writer: anytype) !void {
        assert(self.scale_index == null); // TODO handle SIB

        switch (self.ptr_size) {
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
            switch (self.ptr_size) {
                .byte => try writer.print("0x{x}", .{@intCast(u8, disp_abs)}),
                else => try writer.print("0x{x}", .{disp_abs}),
            }
        }

        try writer.writeByte(']');
    }

    pub fn bitSize(self: Memory) u7 {
        return @intCast(u7, self.ptr_size.bitSize());
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
                        if (immOpBitSize(@bitCast(u32, disp)) == 8) {
                            try encoder.modRm_SIBDisp8(src);
                            if (self.scale_index) |si| {
                                try encoder.sib_scaleIndexBaseDisp8(si.scale, si.index.lowEnc(), dst);
                            } else {
                                try encoder.sib_baseDisp8(dst);
                            }
                            try encoder.disp8(@truncate(i8, disp));
                        } else {
                            try encoder.modRm_SIBDisp32(src);
                            if (self.scale_index) |si| {
                                try encoder.sib_scaleIndexBaseDisp32(si.scale, si.index.lowEnc(), dst);
                            } else {
                                try encoder.sib_baseDisp32(dst);
                            }
                            try encoder.disp32(disp);
                        }
                    }
                } else {
                    if (self.disp == null and dst != 5) {
                        try encoder.modRm_indirectDisp0(src, dst);
                    } else {
                        const disp = self.disp orelse 0;
                        if (immOpBitSize(@bitCast(u32, disp)) == 8) {
                            try encoder.modRm_indirectDisp8(src, dst);
                            try encoder.disp8(@truncate(i8, disp));
                        } else {
                            try encoder.modRm_indirectDisp32(src, dst);
                            try encoder.disp32(disp);
                        }
                    }
                }
            },
            .rip => {
                try encoder.modRm_RIPDisp32(operand);
                try encoder.disp32(self.disp orelse @as(i32, 0));
            },
            .seg => {
                try encoder.modRm_SIBDisp0(operand);
                if (self.scale_index) |si| {
                    try encoder.sib_scaleIndexDisp32(si.scale, si.index.lowEnc());
                } else {
                    try encoder.sib_disp32();
                }
                try encoder.disp32(self.disp orelse @as(i32, 0));
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

    pub fn bitSize(self: RegisterOrMemory) u7 {
        return switch (self) {
            .reg => |r| r.bitSize(),
            .mem => |m| m.bitSize(),
        };
    }
};

inline fn immOpBitSize(u_imm: u32) u6 {
    const imm = @bitCast(i32, u_imm);
    if (math.minInt(i8) <= imm and imm <= math.maxInt(i8)) {
        return 8;
    }
    if (math.minInt(i16) <= imm and imm <= math.maxInt(i16)) {
        return 16;
    }
    return 32;
}

pub inline fn sign(i: anytype) @TypeOf(i) {
    return @as(@TypeOf(i), @boolToInt(i > 0)) - @boolToInt(i < 0);
}
