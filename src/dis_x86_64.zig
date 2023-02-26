const std = @import("std");
const assert = std.debug.assert;
const math = std.math;

const bits = @import("bits.zig");
const decoder = @import("decoder.zig");
const encoder = @import("encoder.zig");

pub const Disassembler = decoder.Disassembler;
pub const Error = decoder.Error;
pub const Instruction = encoder.Instruction;
pub const Register = bits.Register;
pub const Memory = bits.Memory;

test {
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(@import("decoder.zig"));
    std.testing.refAllDecls(@import("encoder.zig"));
    _ = @import("test/encoder.zig");
    // _ = @import("test/decoder.zig"); TODO
}
