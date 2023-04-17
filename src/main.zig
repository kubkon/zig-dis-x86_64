const std = @import("std");
const assert = std.debug.assert;
const math = std.math;

const bits = @import("bits.zig");
const encoder = @import("encoder.zig");

pub const Assembler = @import("Assembler.zig");
pub const Disassembler = @import("Disassembler.zig");
pub const Encoding = @import("Encoding.zig");
pub const Instruction = encoder.Instruction;
pub const Register = bits.Register;
pub const Memory = bits.Memory;
pub const Immediate = bits.Immediate;
pub const StringRepeat = bits.StringRepeat;
pub const StringWidth = bits.StringWidth;

test {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(@import("Assembler.zig"));
    std.testing.refAllDecls(@import("Disassembler.zig"));
    std.testing.refAllDecls(@import("encoder.zig"));
    _ = @import("test/asm.zig");
    _ = @import("test/disasm.zig");
}
