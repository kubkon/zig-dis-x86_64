const std = @import("std");
const assert = std.debug.assert;
const math = std.math;
const expect = std.testing.expect;

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

    ymm0, ymm1, ymm2,  ymm3,  ymm4,  ymm5,  ymm6,  ymm7,
    ymm8, ymm9, ymm10, ymm11, ymm12, ymm13, ymm14, ymm15,

    xmm0, xmm1, xmm2,  xmm3,  xmm4,  xmm5,  xmm6,  xmm7,
    xmm8, xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15,

    es, cs, ss, ds, fs, gs,
    // zig fmt: on

    pub fn gpFromLowEnc(low_enc: u3, is_extended: bool, bit_size: u64) Register {
        const reg_id: u4 = @intCast(u4, @boolToInt(is_extended)) << 3 | low_enc;
        const unsized = @intToEnum(Register, reg_id);
        return unsized.toBitSize(bit_size);
    }

    pub const Class = enum(u2) {
        gp,
        sse,
        seg,
    };

    const class_bits_shift: u3 = 4;

    pub fn id(self: Register) u7 {
        const base_id = @truncate(u4, @enumToInt(self));
        const class_id: u2 = switch (@enumToInt(self)) {
            0...63 => @enumToInt(Class.gp),
            64...95 => @enumToInt(Class.sse),
            96...112 => @enumToInt(Class.seg),
            else => unreachable,
        };
        return @as(u7, class_id) << class_bits_shift | base_id;
    }

    pub fn class(self: Register) Class {
        return @intToEnum(Class, @truncate(u2, self.id() >> class_bits_shift));
    }

    pub fn bitSize(self: Register) u64 {
        return switch (@enumToInt(self)) {
            0...15 => 64,
            16...31 => 32,
            32...47 => 16,
            48...63 => 8,
            64...79 => 256,
            80...95 => 128,
            96...112 => 16,
            else => unreachable,
        };
    }

    pub fn isGp(self: Register) bool {
        return self.class() == .gp;
    }

    pub fn isSegment(self: Register) bool {
        return self.class() == .seg;
    }

    pub fn isSse(self: Register) bool {
        return self.class() == .sse;
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

    pub fn toBitSize(self: Register, bit_size: u64) Register {
        return switch (bit_size) {
            8 => self.to8(),
            16 => self.to16(),
            32 => self.to32(),
            64 => self.to64(),
            128 => self.to128(),
            256 => self.to256(),
            else => unreachable,
        };
    }

    pub fn to64(self: Register) Register {
        assert(self.class() == .gp);
        return @intToEnum(Register, self.enc());
    }

    pub fn to32(self: Register) Register {
        assert(self.class() == .gp);
        return @intToEnum(Register, @as(u8, self.enc()) + 16);
    }

    pub fn to16(self: Register) Register {
        assert(self.class() == .gp);
        return @intToEnum(Register, @as(u8, self.enc()) + 32);
    }

    pub fn to8(self: Register) Register {
        assert(self.class() == .gp);
        return @intToEnum(Register, @as(u8, self.enc()) + 48);
    }

    pub fn to128(self: Register) Register {
        assert(self.class() == .sse);
        return @intToEnum(Register, @as(u8, self.enc()) + 80);
    }

    pub fn to256(self: Register) Register {
        assert(self.class() == .sse);
        return @intToEnum(Register, @as(u8, self.enc()) + 64);
    }

    pub fn fmtPrint(self: Register, writer: anytype) !void {
        try writer.writeAll(@tagName(self));
    }
};

test "Register id - different classes" {
    try expect(Register.al.id() == Register.ax.id());
    try expect(Register.ax.id() == Register.eax.id());
    try expect(Register.eax.id() == Register.rax.id());

    try expect(Register.ymm0.id() == 0b10000);
    try expect(Register.ymm0.id() != Register.rax.id());
    try expect(Register.xmm0.id() == Register.ymm0.id());

    try expect(Register.es.id() == 0b100000);
}

test "Register enc - different classes" {
    try expect(Register.al.enc() == Register.ax.enc());
    try expect(Register.ax.enc() == Register.eax.enc());
    try expect(Register.eax.enc() == Register.rax.enc());
    try expect(Register.ymm0.enc() == Register.rax.enc());
    try expect(Register.xmm0.enc() == Register.ymm0.enc());
    try expect(Register.es.enc() == Register.rax.enc());
}

test "Register classes" {
    try expect(Register.r11.class() == .gp);
    try expect(Register.ymm11.class() == .sse);
    try expect(Register.fs.class() == .seg);
}

pub const Memory = union(enum) {
    sib: Sib,
    rip: Rip,
    moffs: Moffs,

    pub const ScaleIndex = packed struct {
        scale: u4,
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

    pub const Sib = struct {
        ptr_size: PtrSize,
        base: ?Register,
        scale_index: ?ScaleIndex,
        disp: i32,
    };

    pub const Rip = struct {
        ptr_size: PtrSize,
        disp: i32,
    };

    pub const Moffs = struct {
        seg: Register,
        offset: u64,
    };

    pub fn moffs(reg: Register, offset: u64) Memory {
        assert(reg.isSegment());
        return .{ .moffs = .{ .seg = reg, .offset = offset } };
    }

    pub fn sib(ptr_size: PtrSize, args: struct {
        disp: i32,
        base: ?Register = null,
        scale_index: ?ScaleIndex = null,
    }) Memory {
        return .{ .sib = .{
            .base = args.base,
            .disp = args.disp,
            .ptr_size = ptr_size,
            .scale_index = args.scale_index,
        } };
    }

    pub fn rip(ptr_size: PtrSize, disp: i32) Memory {
        return .{ .rip = .{ .ptr_size = ptr_size, .disp = disp } };
    }

    pub fn isSegment(mem: Memory) bool {
        return switch (mem) {
            .moffs => true,
            .rip => false,
            .sib => |s| if (s.base) |r| r.isSegment() else false,
        };
    }

    pub fn base(mem: Memory) ?Register {
        return switch (mem) {
            .moffs => |m| m.seg,
            .sib => |s| s.base,
            .rip => null,
        };
    }

    pub fn scaleIndex(mem: Memory) ?ScaleIndex {
        return switch (mem) {
            .moffs, .rip => null,
            .sib => |s| s.scale_index,
        };
    }

    pub fn bitSize(mem: Memory) u64 {
        return switch (mem) {
            .rip => |r| r.ptr_size.bitSize(),
            .sib => |s| s.ptr_size.bitSize(),
            .moffs => unreachable,
        };
    }

    // pub fn fmtPrint(self: Memory, writer: anytype) !void {
    //     if (self.base == null and self.scale_index == null and !self.rip) {
    //         const disp_abs: u32 = @intCast(u32, try std.math.absInt(self.disp));
    //         if (sign(self.disp) < 0) {
    //             try writer.writeAll("-");
    //         }
    //         try writer.print("0x{x}", .{disp_abs});
    //         return;
    //     }

    //     switch (self.ptr_size) {
    //         .byte => try writer.writeAll("BYTE PTR "),
    //         .word => try writer.writeAll("WORD PTR "),
    //         .dword => try writer.writeAll("DWORD PTR "),
    //         .qword => try writer.writeAll("QWORD PTR "),
    //     }

    //     const base_is_segment_reg = if (self.base) |r| r.isSegment() else false;

    //     if (!base_is_segment_reg) {
    //         try writer.writeByte('[');
    //     }

    //     if (self.base) |r| {
    //         try r.fmtPrint(writer);
    //     } else if (self.rip) {
    //         try writer.writeAll("rip");
    //     }

    //     if (self.scale_index) |si| {
    //         try si.index.fmtPrint(writer);
    //         try writer.print(" * {d}", .{si.scale});
    //     }

    //     if (self.disp != 0) {
    //         const disp_abs: u32 = @intCast(u32, try std.math.absInt(self.disp));
    //         blk: {
    //             if (self.base) |r| {
    //                 if (r.isSegment()) {
    //                     try writer.writeAll(":");
    //                     if (sign(self.disp) < 0) {
    //                         try writer.writeAll("-");
    //                     }
    //                     break :blk;
    //                 }
    //             }
    //             if (sign(self.disp) < 0) {
    //                 try writer.writeAll(" - ");
    //             } else {
    //                 try writer.writeAll(" + ");
    //             }
    //         }
    //         switch (self.ptr_size) {
    //             .byte => try writer.print("0x{x}", .{@intCast(u8, disp_abs)}),
    //             else => try writer.print("0x{x}", .{disp_abs}),
    //         }
    //     }

    //     if (!base_is_segment_reg) {
    //         try writer.writeByte(']');
    //     }
    // }
};

pub inline fn sign(i: anytype) @TypeOf(i) {
    return @as(@TypeOf(i), @boolToInt(i > 0)) - @boolToInt(i < 0);
}
