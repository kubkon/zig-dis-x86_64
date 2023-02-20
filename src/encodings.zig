//! Tabulated list of all encodings.
//! The table format is as follows:
//!
//! tag  | enc | dest bitsize | src bitsize | opcode byte1 | opcode byte2 (or modRM byte) | opcode byte3
//! add  | i   | 64           | 32          | 0x05         | 0x00                         | 0x00
//!
//! TODO convert this file into .zon format when Zig is capable of importing it.

const std = @import("std");
const encoder = @import("encoder.zig");
const Tag = encoder.Instruction.Tag;
const Enc = encoder.Instruction.Enc;

const Entry = std.meta.Tuple(&.{ Tag, Enc, u64, u64, u8, u8, u8 });

fn genArithInst(comptime tag: Tag, op_add: u8, modrm_ext: u8) [19]Entry {
    // zig fmt: off
    return [_]Entry{
        .{ tag, .i,  8,  8,  op_add + 0x04, 0x00,      0x00 },
        .{ tag, .i,  16, 16, op_add + 0x05, 0x00,      0x00 },
        .{ tag, .i,  32, 32, op_add + 0x05, 0x00,      0x00 },
        .{ tag, .i,  64, 32, op_add + 0x05, 0x00,      0x00 },
        .{ tag, .mi, 8,  8,           0x80, modrm_ext, 0x00 },
        .{ tag, .mi, 16, 16,          0x81, modrm_ext, 0x00 },
        .{ tag, .mi, 32, 32,          0x81, modrm_ext, 0x00 },
        .{ tag, .mi, 64, 32,          0x81, modrm_ext, 0x00 },
        .{ tag, .mi, 16, 8,           0x83, modrm_ext, 0x00 },
        .{ tag, .mi, 32, 8,           0x83, modrm_ext, 0x00 },
        .{ tag, .mi, 64, 8,           0x83, modrm_ext, 0x00 },
        .{ tag, .mr, 8,  8,  op_add + 0x00, 0x00,      0x00 },
        .{ tag, .mr, 16, 16, op_add + 0x01, 0x00,      0x00 },
        .{ tag, .mr, 32, 32, op_add + 0x01, 0x00,      0x00 },
        .{ tag, .mr, 64, 64, op_add + 0x01, 0x00,      0x00 },
        .{ tag, .rm, 8,  8,  op_add + 0x02, 0x00,      0x00 },
        .{ tag, .rm, 16, 16, op_add + 0x03, 0x00,      0x00 },
        .{ tag, .rm, 32, 32, op_add + 0x03, 0x00,      0x00 },
        .{ tag, .rm, 64, 64, op_add + 0x03, 0x00,      0x00 },
    };
    // zig fmt: on
}

// zig fmt: off
pub const table = [_]Entry{
    .{ .mov,     .mr, 8,  8,  0x88, 0x00, 0x00 },
    .{ .mov,     .mr, 16, 16, 0x89, 0x00, 0x00 },
    .{ .mov,     .mr, 32, 32, 0x89, 0x00, 0x00 },
    .{ .mov,     .mr, 64, 64, 0x89, 0x00, 0x00 },
    .{ .mov,     .rm, 8,  8,  0x8a, 0x00, 0x00 },
    .{ .mov,     .rm, 16, 16, 0x8b, 0x00, 0x00 },
    .{ .mov,     .rm, 32, 32, 0x8b, 0x00, 0x00 },
    .{ .mov,     .rm, 64, 64, 0x8b, 0x00, 0x00 },
    .{ .mov,     .mr, 16, 0,  0x8c, 0x00, 0x00 },
    .{ .mov,     .mr, 64, 0,  0x8c, 0x00, 0x00 },
    .{ .mov,     .rm, 0,  16, 0x8e, 0x00, 0x00 },
    .{ .mov,     .rm, 0,  64, 0x8e, 0x00, 0x00 },
    .{ .mov,     .fd, 8,  8,  0xa0, 0x00, 0x00 },
    .{ .mov,     .fd, 16, 16, 0xa1, 0x00, 0x00 },
    .{ .mov,     .fd, 32, 32, 0xa1, 0x00, 0x00 },
    .{ .mov,     .fd, 64, 64, 0xa1, 0x00, 0x00 },
    .{ .mov,     .td, 8,  8,  0xa2, 0x00, 0x00 },
    .{ .mov,     .td, 16, 16, 0xa3, 0x00, 0x00 },
    .{ .mov,     .td, 32, 32, 0xa3, 0x00, 0x00 },
    .{ .mov,     .td, 64, 64, 0xa3, 0x00, 0x00 },
    .{ .mov,     .oi, 8,  8,  0xb0, 0x00, 0x00 },
    .{ .mov,     .oi, 16, 16, 0xb8, 0x00, 0x00 },
    .{ .mov,     .oi, 32, 32, 0xb8, 0x00, 0x00 },
    .{ .mov,     .oi, 64, 64, 0xb8, 0x00, 0x00 },
    .{ .mov,     .mi, 8,  8,  0xc6, 0x00, 0x00 },
    .{ .mov,     .mi, 16, 16, 0xc7, 0x00, 0x00 },
    .{ .mov,     .mi, 32, 32, 0xc7, 0x00, 0x00 },
    .{ .mov,     .mi, 64, 32, 0xc7, 0x00, 0x00 },

    .{ .int3,    .np, 0,  0,  0xcc, 0x00, 0x00 },

    .{ .nop,     .np, 0,  0,  0x90, 0x00, 0x00 },

    .{ .ret,     .np, 0,  0,  0xc3, 0x00, 0x00 },

    .{ .syscall, .np, 0,  0,  0x0f, 0x05, 0x00 },
} 
// zig fmt: on
++ genArithInst(.add, 0, 0) ++ genArithInst(.adc, 0x10, 2) ++ genArithInst(.@"and", 0x20, 4) ++
    genArithInst(.cmp, 0x30, 7);
