const Encoding = @import("Encoding.zig");
const Mnemonic = Encoding.Mnemonic;
const OpEn = Encoding.OpEn;
const Op = Encoding.Op;

const Entry = struct { Mnemonic, OpEn, Op, Op, Op, Op, u2, u8, u8, u8, u3 };

// TODO move this into a .zon file when Zig is capable of importing .zon files
pub const table = &[_]Entry{
    .{ .adc, .zi, .al, .imm8, .none, .none, 1, 0x14, 0x00, 0x00, 0 },
    .{ .adc, .zi, .ax, .imm16, .none, .none, 1, 0x15, 0x00, 0x00, 0 },
    .{ .adc, .zi, .eax, .imm32, .none, .none, 1, 0x15, 0x00, 0x00, 0 },
    .{ .adc, .zi, .rax, .imm32, .none, .none, 1, 0x15, 0x00, 0x00, 0 },
    .{ .adc, .mi, .rm8, .imm8, .none, .none, 1, 0x80, 0x00, 0x00, 2 },
    .{ .adc, .mi, .rm16, .imm16, .none, .none, 1, 0x81, 0x00, 0x00, 2 },
    .{ .adc, .mi, .rm32, .imm32, .none, .none, 1, 0x81, 0x00, 0x00, 2 },
    .{ .adc, .mi, .rm64, .imm32, .none, .none, 1, 0x81, 0x00, 0x00, 2 },
    .{ .adc, .mi, .rm16, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 2 },
    .{ .adc, .mi, .rm32, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 2 },
    .{ .adc, .mi, .rm64, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 2 },
    .{ .adc, .mr, .rm8, .r8, .none, .none, 1, 0x10, 0x00, 0x00, 0 },
    .{ .adc, .mr, .rm16, .r16, .none, .none, 1, 0x11, 0x00, 0x00, 0 },
    .{ .adc, .mr, .rm32, .r32, .none, .none, 1, 0x11, 0x00, 0x00, 0 },
    .{ .adc, .mr, .rm64, .r64, .none, .none, 1, 0x11, 0x00, 0x00, 0 },
    .{ .adc, .rm, .r8, .rm8, .none, .none, 1, 0x12, 0x00, 0x00, 0 },
    .{ .adc, .rm, .r16, .rm16, .none, .none, 1, 0x13, 0x00, 0x00, 0 },
    .{ .adc, .rm, .r32, .rm32, .none, .none, 1, 0x13, 0x00, 0x00, 0 },
    .{ .adc, .rm, .r64, .rm64, .none, .none, 1, 0x13, 0x00, 0x00, 0 },

    .{ .add, .zi, .al, .imm8, .none, .none, 1, 0x04, 0x00, 0x00, 0 },
    .{ .add, .zi, .ax, .imm16, .none, .none, 1, 0x05, 0x00, 0x00, 0 },
    .{ .add, .zi, .eax, .imm32, .none, .none, 1, 0x05, 0x00, 0x00, 0 },
    .{ .add, .zi, .rax, .imm32, .none, .none, 1, 0x05, 0x00, 0x00, 0 },
    .{ .add, .mi, .rm8, .imm8, .none, .none, 1, 0x80, 0x00, 0x00, 0 },
    .{ .add, .mi, .rm16, .imm16, .none, .none, 1, 0x81, 0x00, 0x00, 0 },
    .{ .add, .mi, .rm32, .imm32, .none, .none, 1, 0x81, 0x00, 0x00, 0 },
    .{ .add, .mi, .rm64, .imm32, .none, .none, 1, 0x81, 0x00, 0x00, 0 },
    .{ .add, .mi, .rm16, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 0 },
    .{ .add, .mi, .rm32, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 0 },
    .{ .add, .mi, .rm64, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 0 },
    .{ .add, .mr, .rm8, .r8, .none, .none, 1, 0x00, 0x00, 0x00, 0 },
    .{ .add, .mr, .rm16, .r16, .none, .none, 1, 0x01, 0x00, 0x00, 0 },
    .{ .add, .mr, .rm32, .r32, .none, .none, 1, 0x01, 0x00, 0x00, 0 },
    .{ .add, .mr, .rm64, .r64, .none, .none, 1, 0x01, 0x00, 0x00, 0 },
    .{ .add, .rm, .r8, .rm8, .none, .none, 1, 0x02, 0x00, 0x00, 0 },
    .{ .add, .rm, .r16, .rm16, .none, .none, 1, 0x03, 0x00, 0x00, 0 },
    .{ .add, .rm, .r32, .rm32, .none, .none, 1, 0x03, 0x00, 0x00, 0 },
    .{ .add, .rm, .r64, .rm64, .none, .none, 1, 0x03, 0x00, 0x00, 0 },

    .{ .@"and", .zi, .al, .imm8, .none, .none, 1, 0x24, 0x00, 0x00, 0 },
    .{ .@"and", .zi, .ax, .imm16, .none, .none, 1, 0x25, 0x00, 0x00, 0 },
    .{ .@"and", .zi, .eax, .imm32, .none, .none, 1, 0x25, 0x00, 0x00, 0 },
    .{ .@"and", .zi, .rax, .imm32, .none, .none, 1, 0x25, 0x00, 0x00, 0 },
    .{ .@"and", .mi, .rm8, .imm8, .none, .none, 1, 0x80, 0x00, 0x00, 4 },
    .{ .@"and", .mi, .rm16, .imm16, .none, .none, 1, 0x81, 0x00, 0x00, 4 },
    .{ .@"and", .mi, .rm32, .imm32, .none, .none, 1, 0x81, 0x00, 0x00, 4 },
    .{ .@"and", .mi, .rm64, .imm32, .none, .none, 1, 0x81, 0x00, 0x00, 4 },
    .{ .@"and", .mi, .rm16, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 4 },
    .{ .@"and", .mi, .rm32, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 4 },
    .{ .@"and", .mi, .rm64, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 4 },
    .{ .@"and", .mr, .rm8, .r8, .none, .none, 1, 0x20, 0x00, 0x00, 0 },
    .{ .@"and", .mr, .rm16, .r16, .none, .none, 1, 0x21, 0x00, 0x00, 0 },
    .{ .@"and", .mr, .rm32, .r32, .none, .none, 1, 0x21, 0x00, 0x00, 0 },
    .{ .@"and", .mr, .rm64, .r64, .none, .none, 1, 0x21, 0x00, 0x00, 0 },
    .{ .@"and", .rm, .r8, .rm8, .none, .none, 1, 0x22, 0x00, 0x00, 0 },
    .{ .@"and", .rm, .r16, .rm16, .none, .none, 1, 0x23, 0x00, 0x00, 0 },
    .{ .@"and", .rm, .r32, .rm32, .none, .none, 1, 0x23, 0x00, 0x00, 0 },
    .{ .@"and", .rm, .r64, .rm64, .none, .none, 1, 0x23, 0x00, 0x00, 0 },

    // This is M encoding according to Intel, but D makes more sense here.
    .{ .call, .d, .rel32, .none, .none, .none, 1, 0xe8, 0x00, 0x00, 0 },
    .{ .call, .m, .rm64, .none, .none, .none, 1, 0xff, 0x00, 0x00, 2 },

    .{ .cbw, .np, .none, .none, .none, .none, 1, 0x98, 0x00, 0x00, 0 },
    .{ .cwde, .np, .none, .none, .none, .none, 1, 0x98, 0x00, 0x00, 0 },
    .{ .cdqe, .np, .none, .none, .none, .none, 1, 0x98, 0x00, 0x00, 0 },

    .{ .cmova, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x47, 0x00, 0 },
    .{ .cmova, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x47, 0x00, 0 },
    .{ .cmova, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x47, 0x00, 0 },
    .{ .cmovae, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x43, 0x00, 0 },
    .{ .cmovae, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x43, 0x00, 0 },
    .{ .cmovae, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x43, 0x00, 0 },
    .{ .cmovb, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x42, 0x00, 0 },
    .{ .cmovb, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x42, 0x00, 0 },
    .{ .cmovb, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x42, 0x00, 0 },
    .{ .cmovbe, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x46, 0x00, 0 },
    .{ .cmovbe, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x46, 0x00, 0 },
    .{ .cmovbe, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x46, 0x00, 0 },
    .{ .cmovc, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x42, 0x00, 0 },
    .{ .cmovc, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x42, 0x00, 0 },
    .{ .cmovc, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x42, 0x00, 0 },
    .{ .cmove, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x44, 0x00, 0 },
    .{ .cmove, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x44, 0x00, 0 },
    .{ .cmove, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x44, 0x00, 0 },
    .{ .cmovg, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x4f, 0x00, 0 },
    .{ .cmovg, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x4f, 0x00, 0 },
    .{ .cmovg, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x4f, 0x00, 0 },
    .{ .cmovge, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x4d, 0x00, 0 },
    .{ .cmovge, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x4d, 0x00, 0 },
    .{ .cmovge, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x4d, 0x00, 0 },
    .{ .cmovl, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x4c, 0x00, 0 },
    .{ .cmovl, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x4c, 0x00, 0 },
    .{ .cmovl, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x4c, 0x00, 0 },
    .{ .cmovle, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x4e, 0x00, 0 },
    .{ .cmovle, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x4e, 0x00, 0 },
    .{ .cmovle, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x4e, 0x00, 0 },
    .{ .cmovna, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x46, 0x00, 0 },
    .{ .cmovna, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x46, 0x00, 0 },
    .{ .cmovna, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x46, 0x00, 0 },
    .{ .cmovnae, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x42, 0x00, 0 },
    .{ .cmovnae, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x42, 0x00, 0 },
    .{ .cmovnae, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x42, 0x00, 0 },
    .{ .cmovnb, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x43, 0x00, 0 },
    .{ .cmovnb, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x43, 0x00, 0 },
    .{ .cmovnb, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x43, 0x00, 0 },
    .{ .cmovnbe, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x47, 0x00, 0 },
    .{ .cmovnbe, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x47, 0x00, 0 },
    .{ .cmovnbe, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x47, 0x00, 0 },
    .{ .cmovnc, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x43, 0x00, 0 },
    .{ .cmovnc, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x43, 0x00, 0 },
    .{ .cmovnc, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x43, 0x00, 0 },
    .{ .cmovne, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x45, 0x00, 0 },
    .{ .cmovne, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x45, 0x00, 0 },
    .{ .cmovne, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x45, 0x00, 0 },
    .{ .cmovng, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x4e, 0x00, 0 },
    .{ .cmovng, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x4e, 0x00, 0 },
    .{ .cmovng, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x4e, 0x00, 0 },
    .{ .cmovnge, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x4c, 0x00, 0 },
    .{ .cmovnge, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x4c, 0x00, 0 },
    .{ .cmovnge, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x4c, 0x00, 0 },
    .{ .cmovnl, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x4d, 0x00, 0 },
    .{ .cmovnl, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x4d, 0x00, 0 },
    .{ .cmovnl, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x4d, 0x00, 0 },
    .{ .cmovnle, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x4f, 0x00, 0 },
    .{ .cmovnle, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x4f, 0x00, 0 },
    .{ .cmovnle, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x4f, 0x00, 0 },
    .{ .cmovno, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x41, 0x00, 0 },
    .{ .cmovno, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x41, 0x00, 0 },
    .{ .cmovno, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x41, 0x00, 0 },
    .{ .cmovnp, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x4b, 0x00, 0 },
    .{ .cmovnp, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x4b, 0x00, 0 },
    .{ .cmovnp, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x4b, 0x00, 0 },
    .{ .cmovns, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x49, 0x00, 0 },
    .{ .cmovns, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x49, 0x00, 0 },
    .{ .cmovns, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x49, 0x00, 0 },
    .{ .cmovnz, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x45, 0x00, 0 },
    .{ .cmovnz, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x45, 0x00, 0 },
    .{ .cmovnz, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x45, 0x00, 0 },
    .{ .cmovo, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x40, 0x00, 0 },
    .{ .cmovo, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x40, 0x00, 0 },
    .{ .cmovo, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x40, 0x00, 0 },
    .{ .cmovp, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x4a, 0x00, 0 },
    .{ .cmovp, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x4a, 0x00, 0 },
    .{ .cmovp, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x4a, 0x00, 0 },
    .{ .cmovpe, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x4a, 0x00, 0 },
    .{ .cmovpe, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x4a, 0x00, 0 },
    .{ .cmovpe, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x4a, 0x00, 0 },
    .{ .cmovpo, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x4b, 0x00, 0 },
    .{ .cmovpo, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x4b, 0x00, 0 },
    .{ .cmovpo, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x4b, 0x00, 0 },
    .{ .cmovs, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x48, 0x00, 0 },
    .{ .cmovs, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x48, 0x00, 0 },
    .{ .cmovs, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x48, 0x00, 0 },
    .{ .cmovz, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0x44, 0x00, 0 },
    .{ .cmovz, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0x44, 0x00, 0 },
    .{ .cmovz, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0x44, 0x00, 0 },

    .{ .cmp, .zi, .al, .imm8, .none, .none, 1, 0x3c, 0x00, 0x00, 0 },
    .{ .cmp, .zi, .ax, .imm16, .none, .none, 1, 0x3d, 0x00, 0x00, 0 },
    .{ .cmp, .zi, .eax, .imm32, .none, .none, 1, 0x3d, 0x00, 0x00, 0 },
    .{ .cmp, .zi, .rax, .imm32, .none, .none, 1, 0x3d, 0x00, 0x00, 0 },
    .{ .cmp, .mi, .rm8, .imm8, .none, .none, 1, 0x80, 0x00, 0x00, 7 },
    .{ .cmp, .mi, .rm16, .imm16, .none, .none, 1, 0x81, 0x00, 0x00, 7 },
    .{ .cmp, .mi, .rm32, .imm32, .none, .none, 1, 0x81, 0x00, 0x00, 7 },
    .{ .cmp, .mi, .rm64, .imm32, .none, .none, 1, 0x81, 0x00, 0x00, 7 },
    .{ .cmp, .mi, .rm16, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 7 },
    .{ .cmp, .mi, .rm32, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 7 },
    .{ .cmp, .mi, .rm64, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 7 },
    .{ .cmp, .mr, .rm8, .r8, .none, .none, 1, 0x38, 0x00, 0x00, 0 },
    .{ .cmp, .mr, .rm16, .r16, .none, .none, 1, 0x39, 0x00, 0x00, 0 },
    .{ .cmp, .mr, .rm32, .r32, .none, .none, 1, 0x39, 0x00, 0x00, 0 },
    .{ .cmp, .mr, .rm64, .r64, .none, .none, 1, 0x39, 0x00, 0x00, 0 },
    .{ .cmp, .rm, .r8, .rm8, .none, .none, 1, 0x3a, 0x00, 0x00, 0 },
    .{ .cmp, .rm, .r16, .rm16, .none, .none, 1, 0x3b, 0x00, 0x00, 0 },
    .{ .cmp, .rm, .r32, .rm32, .none, .none, 1, 0x3b, 0x00, 0x00, 0 },
    .{ .cmp, .rm, .r64, .rm64, .none, .none, 1, 0x3b, 0x00, 0x00, 0 },

    .{ .div, .m, .rm8, .none, .none, .none, 1, 0xf6, 0x00, 0x00, 6 },
    .{ .div, .m, .rm16, .none, .none, .none, 1, 0xf7, 0x00, 0x00, 6 },
    .{ .div, .m, .rm32, .none, .none, .none, 1, 0xf7, 0x00, 0x00, 6 },
    .{ .div, .m, .rm64, .none, .none, .none, 1, 0xf7, 0x00, 0x00, 6 },

    .{ .idiv, .m, .rm8, .none, .none, .none, 1, 0xf6, 0x00, 0x00, 7 },
    .{ .idiv, .m, .rm16, .none, .none, .none, 1, 0xf7, 0x00, 0x00, 7 },
    .{ .idiv, .m, .rm32, .none, .none, .none, 1, 0xf7, 0x00, 0x00, 7 },
    .{ .idiv, .m, .rm64, .none, .none, .none, 1, 0xf7, 0x00, 0x00, 7 },

    .{ .imul, .m, .rm8, .none, .none, .none, 1, 0xf6, 0x00, 0x00, 5 },
    .{ .imul, .m, .rm16, .none, .none, .none, 1, 0xf7, 0x00, 0x00, 5 },
    .{ .imul, .m, .rm32, .none, .none, .none, 1, 0xf7, 0x00, 0x00, 5 },
    .{ .imul, .m, .rm64, .none, .none, .none, 1, 0xf7, 0x00, 0x00, 5 },
    .{ .imul, .rm, .r16, .rm16, .none, .none, 2, 0x0f, 0xaf, 0x00, 0 },
    .{ .imul, .rm, .r32, .rm32, .none, .none, 2, 0x0f, 0xaf, 0x00, 0 },
    .{ .imul, .rm, .r64, .rm64, .none, .none, 2, 0x0f, 0xaf, 0x00, 0 },
    .{ .imul, .rmi, .r16, .rm16, .imm8, .none, 1, 0x6b, 0x00, 0x00, 0 },
    .{ .imul, .rmi, .r32, .rm32, .imm8, .none, 1, 0x6b, 0x00, 0x00, 0 },
    .{ .imul, .rmi, .r64, .rm64, .imm8, .none, 1, 0x6b, 0x00, 0x00, 0 },
    .{ .imul, .rmi, .r16, .rm16, .imm16, .none, 1, 0x69, 0x00, 0x00, 0 },
    .{ .imul, .rmi, .r32, .rm32, .imm32, .none, 1, 0x69, 0x00, 0x00, 0 },
    .{ .imul, .rmi, .r64, .rm64, .imm32, .none, 1, 0x69, 0x00, 0x00, 0 },

    .{ .int3, .np, .none, .none, .none, .none, 1, 0xcc, 0x00, 0x00, 0 },

    .{ .ja, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x87, 0x00, 0 },
    .{ .jae, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x83, 0x00, 0 },
    .{ .jb, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x82, 0x00, 0 },
    .{ .jbe, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x86, 0x00, 0 },
    .{ .jc, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x82, 0x00, 0 },
    .{ .jrcxz, .d, .rel32, .none, .none, .none, 1, 0xe3, 0x00, 0x00, 0 },
    .{ .je, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x84, 0x00, 0 },
    .{ .jg, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x8f, 0x00, 0 },
    .{ .jge, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x8d, 0x00, 0 },
    .{ .jl, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x8c, 0x00, 0 },
    .{ .jle, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x8e, 0x00, 0 },
    .{ .jna, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x86, 0x00, 0 },
    .{ .jnae, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x82, 0x00, 0 },
    .{ .jnb, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x83, 0x00, 0 },
    .{ .jnbe, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x87, 0x00, 0 },
    .{ .jnc, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x83, 0x00, 0 },
    .{ .jne, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x85, 0x00, 0 },
    .{ .jng, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x8e, 0x00, 0 },
    .{ .jnge, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x8c, 0x00, 0 },
    .{ .jnl, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x8d, 0x00, 0 },
    .{ .jnle, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x8f, 0x00, 0 },
    .{ .jno, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x81, 0x00, 0 },
    .{ .jnp, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x8b, 0x00, 0 },
    .{ .jns, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x89, 0x00, 0 },
    .{ .jnz, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x85, 0x00, 0 },
    .{ .jo, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x80, 0x00, 0 },
    .{ .jp, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x8a, 0x00, 0 },
    .{ .jpe, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x8a, 0x00, 0 },
    .{ .jpo, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x8b, 0x00, 0 },
    .{ .js, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x88, 0x00, 0 },
    .{ .jz, .d, .rel32, .none, .none, .none, 2, 0x0f, 0x84, 0x00, 0 },

    .{ .jmp, .d, .rel32, .none, .none, .none, 1, 0xe9, 0x00, 0x00, 0 },
    .{ .jmp, .m, .rm64, .none, .none, .none, 1, 0xff, 0x00, 0x00, 4 },

    .{ .lea, .rm, .r16, .m, .none, .none, 1, 0x8d, 0x00, 0x00, 0 },
    .{ .lea, .rm, .r32, .m, .none, .none, 1, 0x8d, 0x00, 0x00, 0 },
    .{ .lea, .rm, .r64, .m, .none, .none, 1, 0x8d, 0x00, 0x00, 0 },

    .{ .mov, .mr, .rm8, .r8, .none, .none, 1, 0x88, 0x00, 0x00, 0 },
    .{ .mov, .mr, .rm16, .r16, .none, .none, 1, 0x89, 0x00, 0x00, 0 },
    .{ .mov, .mr, .rm32, .r32, .none, .none, 1, 0x89, 0x00, 0x00, 0 },
    .{ .mov, .mr, .rm64, .r64, .none, .none, 1, 0x89, 0x00, 0x00, 0 },
    .{ .mov, .rm, .r8, .rm8, .none, .none, 1, 0x8a, 0x00, 0x00, 0 },
    .{ .mov, .rm, .r16, .rm16, .none, .none, 1, 0x8b, 0x00, 0x00, 0 },
    .{ .mov, .rm, .r32, .rm32, .none, .none, 1, 0x8b, 0x00, 0x00, 0 },
    .{ .mov, .rm, .r64, .rm64, .none, .none, 1, 0x8b, 0x00, 0x00, 0 },
    .{ .mov, .mr, .rm16, .sreg, .none, .none, 1, 0x8c, 0x00, 0x00, 0 },
    .{ .mov, .mr, .rm64, .sreg, .none, .none, 1, 0x8c, 0x00, 0x00, 0 },
    .{ .mov, .rm, .sreg, .rm16, .none, .none, 1, 0x8e, 0x00, 0x00, 0 },
    .{ .mov, .rm, .sreg, .rm64, .none, .none, 1, 0x8e, 0x00, 0x00, 0 },
    .{ .mov, .fd, .al, .moffs, .none, .none, 1, 0xa0, 0x00, 0x00, 0 },
    .{ .mov, .fd, .ax, .moffs, .none, .none, 1, 0xa1, 0x00, 0x00, 0 },
    .{ .mov, .fd, .eax, .moffs, .none, .none, 1, 0xa1, 0x00, 0x00, 0 },
    .{ .mov, .fd, .rax, .moffs, .none, .none, 1, 0xa1, 0x00, 0x00, 0 },
    .{ .mov, .td, .moffs, .al, .none, .none, 1, 0xa2, 0x00, 0x00, 0 },
    .{ .mov, .td, .moffs, .ax, .none, .none, 1, 0xa3, 0x00, 0x00, 0 },
    .{ .mov, .td, .moffs, .eax, .none, .none, 1, 0xa3, 0x00, 0x00, 0 },
    .{ .mov, .td, .moffs, .rax, .none, .none, 1, 0xa3, 0x00, 0x00, 0 },
    .{ .mov, .oi, .r8, .imm8, .none, .none, 1, 0xb0, 0x00, 0x00, 0 },
    .{ .mov, .oi, .r16, .imm16, .none, .none, 1, 0xb8, 0x00, 0x00, 0 },
    .{ .mov, .oi, .r32, .imm32, .none, .none, 1, 0xb8, 0x00, 0x00, 0 },
    .{ .mov, .oi, .r64, .imm64, .none, .none, 1, 0xb8, 0x00, 0x00, 0 },
    .{ .mov, .mi, .rm8, .imm8, .none, .none, 1, 0xc6, 0x00, 0x00, 0 },
    .{ .mov, .mi, .rm16, .imm16, .none, .none, 1, 0xc7, 0x00, 0x00, 0 },
    .{ .mov, .mi, .rm32, .imm32, .none, .none, 1, 0xc7, 0x00, 0x00, 0 },
    .{ .mov, .mi, .rm64, .imm32, .none, .none, 1, 0xc7, 0x00, 0x00, 0 },

    .{ .movsx, .rm, .r16, .rm8, .none, .none, 2, 0x0f, 0xbe, 0x00, 0 },
    .{ .movsx, .rm, .r32, .rm8, .none, .none, 2, 0x0f, 0xbe, 0x00, 0 },
    .{ .movsx, .rm, .r64, .rm8, .none, .none, 2, 0x0f, 0xbe, 0x00, 0 },
    .{ .movsx, .rm, .r32, .rm16, .none, .none, 2, 0x0f, 0xbf, 0x00, 0 },
    .{ .movsx, .rm, .r64, .rm16, .none, .none, 2, 0x0f, 0xbf, 0x00, 0 },

    .{ .movsxd, .rm, .r64, .rm32, .none, .none, 1, 0x63, 0x00, 0x00, 0 },

    .{ .movzx, .rm, .r16, .rm8, .none, .none, 2, 0x0f, 0xb6, 0x00, 0 },
    .{ .movzx, .rm, .r32, .rm8, .none, .none, 2, 0x0f, 0xb6, 0x00, 0 },
    .{ .movzx, .rm, .r64, .rm8, .none, .none, 2, 0x0f, 0xb6, 0x00, 0 },
    .{ .movzx, .rm, .r32, .rm16, .none, .none, 2, 0x0f, 0xb7, 0x00, 0 },
    .{ .movzx, .rm, .r64, .rm16, .none, .none, 2, 0x0f, 0xb7, 0x00, 0 },

    .{ .mul, .m, .rm8, .none, .none, .none, 1, 0xf6, 0x00, 0x00, 4 },
    .{ .mul, .m, .rm16, .none, .none, .none, 1, 0xf7, 0x00, 0x00, 4 },
    .{ .mul, .m, .rm32, .none, .none, .none, 1, 0xf7, 0x00, 0x00, 4 },
    .{ .mul, .m, .rm64, .none, .none, .none, 1, 0xf7, 0x00, 0x00, 4 },

    .{ .nop, .np, .none, .none, .none, .none, 1, 0x90, 0x00, 0x00, 0 },

    .{ .@"or", .zi, .al, .imm8, .none, .none, 1, 0x0c, 0x00, 0x00, 0 },
    .{ .@"or", .zi, .ax, .imm16, .none, .none, 1, 0x0d, 0x00, 0x00, 0 },
    .{ .@"or", .zi, .eax, .imm32, .none, .none, 1, 0x0d, 0x00, 0x00, 0 },
    .{ .@"or", .zi, .rax, .imm32, .none, .none, 1, 0x0d, 0x00, 0x00, 0 },
    .{ .@"or", .mi, .rm8, .imm8, .none, .none, 1, 0x80, 0x00, 0x00, 1 },
    .{ .@"or", .mi, .rm16, .imm16, .none, .none, 1, 0x81, 0x00, 0x00, 1 },
    .{ .@"or", .mi, .rm32, .imm32, .none, .none, 1, 0x81, 0x00, 0x00, 1 },
    .{ .@"or", .mi, .rm64, .imm32, .none, .none, 1, 0x81, 0x00, 0x00, 1 },
    .{ .@"or", .mi, .rm16, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 1 },
    .{ .@"or", .mi, .rm32, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 1 },
    .{ .@"or", .mi, .rm64, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 1 },
    .{ .@"or", .mr, .rm8, .r8, .none, .none, 1, 0x08, 0x00, 0x00, 0 },
    .{ .@"or", .mr, .rm16, .r16, .none, .none, 1, 0x09, 0x00, 0x00, 0 },
    .{ .@"or", .mr, .rm32, .r32, .none, .none, 1, 0x09, 0x00, 0x00, 0 },
    .{ .@"or", .mr, .rm64, .r64, .none, .none, 1, 0x09, 0x00, 0x00, 0 },
    .{ .@"or", .rm, .r8, .rm8, .none, .none, 1, 0x0a, 0x00, 0x00, 0 },
    .{ .@"or", .rm, .r16, .rm16, .none, .none, 1, 0x0b, 0x00, 0x00, 0 },
    .{ .@"or", .rm, .r32, .rm32, .none, .none, 1, 0x0b, 0x00, 0x00, 0 },
    .{ .@"or", .rm, .r64, .rm64, .none, .none, 1, 0x0b, 0x00, 0x00, 0 },

    .{ .pop, .o, .r16, .none, .none, .none, 1, 0x58, 0x00, 0x00, 0 },
    .{ .pop, .o, .r64, .none, .none, .none, 1, 0x58, 0x00, 0x00, 0 },
    .{ .pop, .m, .rm16, .none, .none, .none, 1, 0x8f, 0x00, 0x00, 0 },
    .{ .pop, .m, .rm64, .none, .none, .none, 1, 0x8f, 0x00, 0x00, 0 },

    .{ .push, .o, .r16, .none, .none, .none, 1, 0x50, 0x00, 0x00, 0 },
    .{ .push, .o, .r64, .none, .none, .none, 1, 0x50, 0x00, 0x00, 0 },
    .{ .push, .m, .rm16, .none, .none, .none, 1, 0xff, 0x0, 0x00, 6 },
    .{ .push, .m, .rm64, .none, .none, .none, 1, 0xff, 0x0, 0x00, 6 },
    .{ .push, .i, .imm8, .none, .none, .none, 1, 0x6a, 0x00, 0x00, 0 },
    .{ .push, .i, .imm16, .none, .none, .none, 1, 0x68, 0x00, 0x00, 0 },
    .{ .push, .i, .imm32, .none, .none, .none, 1, 0x68, 0x00, 0x00, 0 },

    .{ .ret, .np, .none, .none, .none, .none, 1, 0xc3, 0x00, 0x00, 0 },

    .{ .sal, .m1, .rm8, .unity, .none, .none, 1, 0xd0, 0x00, 0x00, 4 },
    .{ .sal, .m1, .rm16, .unity, .none, .none, 1, 0xd1, 0x00, 0x00, 4 },
    .{ .sal, .m1, .rm32, .unity, .none, .none, 1, 0xd1, 0x00, 0x00, 4 },
    .{ .sal, .m1, .rm64, .unity, .none, .none, 1, 0xd1, 0x00, 0x00, 4 },
    .{ .sal, .mc, .rm8, .cl, .none, .none, 1, 0xd2, 0x00, 0x00, 4 },
    .{ .sal, .mc, .rm16, .cl, .none, .none, 1, 0xd3, 0x00, 0x00, 4 },
    .{ .sal, .mc, .rm32, .cl, .none, .none, 1, 0xd3, 0x00, 0x00, 4 },
    .{ .sal, .mc, .rm64, .cl, .none, .none, 1, 0xd3, 0x00, 0x00, 4 },
    .{ .sal, .mi, .rm8, .imm8, .none, .none, 1, 0xc0, 0x00, 0x00, 4 },
    .{ .sal, .mi, .rm16, .imm8, .none, .none, 1, 0xc1, 0x00, 0x00, 4 },
    .{ .sal, .mi, .rm32, .imm8, .none, .none, 1, 0xc1, 0x00, 0x00, 4 },
    .{ .sal, .mi, .rm64, .imm8, .none, .none, 1, 0xc1, 0x00, 0x00, 4 },

    .{ .sar, .m1, .rm8, .unity, .none, .none, 1, 0xd0, 0x00, 0x00, 7 },
    .{ .sar, .m1, .rm16, .unity, .none, .none, 1, 0xd1, 0x00, 0x00, 7 },
    .{ .sar, .m1, .rm32, .unity, .none, .none, 1, 0xd1, 0x00, 0x00, 7 },
    .{ .sar, .m1, .rm64, .unity, .none, .none, 1, 0xd1, 0x00, 0x00, 7 },
    .{ .sar, .mc, .rm8, .cl, .none, .none, 1, 0xd2, 0x00, 0x00, 7 },
    .{ .sar, .mc, .rm16, .cl, .none, .none, 1, 0xd3, 0x00, 0x00, 7 },
    .{ .sar, .mc, .rm32, .cl, .none, .none, 1, 0xd3, 0x00, 0x00, 7 },
    .{ .sar, .mc, .rm64, .cl, .none, .none, 1, 0xd3, 0x00, 0x00, 7 },
    .{ .sar, .mi, .rm8, .imm8, .none, .none, 1, 0xc0, 0x00, 0x00, 7 },
    .{ .sar, .mi, .rm16, .imm8, .none, .none, 1, 0xc1, 0x00, 0x00, 7 },
    .{ .sar, .mi, .rm32, .imm8, .none, .none, 1, 0xc1, 0x00, 0x00, 7 },
    .{ .sar, .mi, .rm64, .imm8, .none, .none, 1, 0xc1, 0x00, 0x00, 7 },

    .{ .sbb, .zi, .al, .imm8, .none, .none, 1, 0x1c, 0x00, 0x00, 0 },
    .{ .sbb, .zi, .ax, .imm16, .none, .none, 1, 0x1d, 0x00, 0x00, 0 },
    .{ .sbb, .zi, .eax, .imm32, .none, .none, 1, 0x1d, 0x00, 0x00, 0 },
    .{ .sbb, .zi, .rax, .imm32, .none, .none, 1, 0x1d, 0x00, 0x00, 0 },
    .{ .sbb, .mi, .rm8, .imm8, .none, .none, 1, 0x80, 0x00, 0x00, 3 },
    .{ .sbb, .mi, .rm16, .imm16, .none, .none, 1, 0x81, 0x00, 0x00, 3 },
    .{ .sbb, .mi, .rm32, .imm32, .none, .none, 1, 0x81, 0x00, 0x00, 3 },
    .{ .sbb, .mi, .rm64, .imm32, .none, .none, 1, 0x81, 0x00, 0x00, 3 },
    .{ .sbb, .mi, .rm16, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 3 },
    .{ .sbb, .mi, .rm32, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 3 },
    .{ .sbb, .mi, .rm64, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 3 },
    .{ .sbb, .mr, .rm8, .r8, .none, .none, 1, 0x18, 0x00, 0x00, 0 },
    .{ .sbb, .mr, .rm16, .r16, .none, .none, 1, 0x19, 0x00, 0x00, 0 },
    .{ .sbb, .mr, .rm32, .r32, .none, .none, 1, 0x19, 0x00, 0x00, 0 },
    .{ .sbb, .mr, .rm64, .r64, .none, .none, 1, 0x19, 0x00, 0x00, 0 },
    .{ .sbb, .rm, .r8, .rm8, .none, .none, 1, 0x1a, 0x00, 0x00, 0 },
    .{ .sbb, .rm, .r16, .rm16, .none, .none, 1, 0x1b, 0x00, 0x00, 0 },
    .{ .sbb, .rm, .r32, .rm32, .none, .none, 1, 0x1b, 0x00, 0x00, 0 },
    .{ .sbb, .rm, .r64, .rm64, .none, .none, 1, 0x1b, 0x00, 0x00, 0 },

    .{ .seta, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x97, 0x00, 0 },
    .{ .setae, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x93, 0x00, 0 },
    .{ .setb, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x92, 0x00, 0 },
    .{ .setbe, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x96, 0x00, 0 },
    .{ .setc, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x92, 0x00, 0 },
    .{ .sete, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x94, 0x00, 0 },
    .{ .setg, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x9f, 0x00, 0 },
    .{ .setge, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x9d, 0x00, 0 },
    .{ .setl, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x9c, 0x00, 0 },
    .{ .setle, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x9e, 0x00, 0 },
    .{ .setna, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x96, 0x00, 0 },
    .{ .setnae, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x92, 0x00, 0 },
    .{ .setnb, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x93, 0x00, 0 },
    .{ .setnbe, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x97, 0x00, 0 },
    .{ .setnc, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x93, 0x00, 0 },
    .{ .setne, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x95, 0x00, 0 },
    .{ .setng, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x9e, 0x00, 0 },
    .{ .setnge, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x9c, 0x00, 0 },
    .{ .setnl, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x9d, 0x00, 0 },
    .{ .setnle, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x9f, 0x00, 0 },
    .{ .setno, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x91, 0x00, 0 },
    .{ .setnp, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x9b, 0x00, 0 },
    .{ .setns, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x99, 0x00, 0 },
    .{ .setnz, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x95, 0x00, 0 },
    .{ .seto, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x90, 0x00, 0 },
    .{ .setp, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x9a, 0x00, 0 },
    .{ .setpe, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x9a, 0x00, 0 },
    .{ .setpo, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x9b, 0x00, 0 },
    .{ .sets, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x98, 0x00, 0 },
    .{ .setz, .m, .rm8, .none, .none, .none, 2, 0x0f, 0x94, 0x00, 0 },

    .{ .shl, .m1, .rm8, .unity, .none, .none, 1, 0xd0, 0x00, 0x00, 4 },
    .{ .shl, .m1, .rm16, .unity, .none, .none, 1, 0xd1, 0x00, 0x00, 4 },
    .{ .shl, .m1, .rm32, .unity, .none, .none, 1, 0xd1, 0x00, 0x00, 4 },
    .{ .shl, .m1, .rm64, .unity, .none, .none, 1, 0xd1, 0x00, 0x00, 4 },
    .{ .shl, .mc, .rm8, .cl, .none, .none, 1, 0xd2, 0x00, 0x00, 4 },
    .{ .shl, .mc, .rm16, .cl, .none, .none, 1, 0xd3, 0x00, 0x00, 4 },
    .{ .shl, .mc, .rm32, .cl, .none, .none, 1, 0xd3, 0x00, 0x00, 4 },
    .{ .shl, .mc, .rm64, .cl, .none, .none, 1, 0xd3, 0x00, 0x00, 4 },
    .{ .shl, .mi, .rm8, .imm8, .none, .none, 1, 0xc0, 0x00, 0x00, 4 },
    .{ .shl, .mi, .rm16, .imm8, .none, .none, 1, 0xc1, 0x00, 0x00, 4 },
    .{ .shl, .mi, .rm32, .imm8, .none, .none, 1, 0xc1, 0x00, 0x00, 4 },
    .{ .shl, .mi, .rm64, .imm8, .none, .none, 1, 0xc1, 0x00, 0x00, 4 },

    .{ .shr, .m1, .rm8, .unity, .none, .none, 1, 0xd0, 0x00, 0x00, 5 },
    .{ .shr, .m1, .rm16, .unity, .none, .none, 1, 0xd1, 0x00, 0x00, 5 },
    .{ .shr, .m1, .rm32, .unity, .none, .none, 1, 0xd1, 0x00, 0x00, 5 },
    .{ .shr, .m1, .rm64, .unity, .none, .none, 1, 0xd1, 0x00, 0x00, 5 },
    .{ .shr, .mc, .rm8, .cl, .none, .none, 1, 0xd2, 0x00, 0x00, 5 },
    .{ .shr, .mc, .rm16, .cl, .none, .none, 1, 0xd3, 0x00, 0x00, 5 },
    .{ .shr, .mc, .rm32, .cl, .none, .none, 1, 0xd3, 0x00, 0x00, 5 },
    .{ .shr, .mc, .rm64, .cl, .none, .none, 1, 0xd3, 0x00, 0x00, 5 },
    .{ .shr, .mi, .rm8, .imm8, .none, .none, 1, 0xc0, 0x00, 0x00, 5 },
    .{ .shr, .mi, .rm16, .imm8, .none, .none, 1, 0xc1, 0x00, 0x00, 5 },
    .{ .shr, .mi, .rm32, .imm8, .none, .none, 1, 0xc1, 0x00, 0x00, 5 },
    .{ .shr, .mi, .rm64, .imm8, .none, .none, 1, 0xc1, 0x00, 0x00, 5 },

    .{ .sub, .zi, .al, .imm8, .none, .none, 1, 0x2c, 0x00, 0x00, 0 },
    .{ .sub, .zi, .ax, .imm16, .none, .none, 1, 0x2d, 0x00, 0x00, 0 },
    .{ .sub, .zi, .eax, .imm32, .none, .none, 1, 0x2d, 0x00, 0x00, 0 },
    .{ .sub, .zi, .rax, .imm32, .none, .none, 1, 0x2d, 0x00, 0x00, 0 },
    .{ .sub, .mi, .rm8, .imm8, .none, .none, 1, 0x80, 0x00, 0x00, 5 },
    .{ .sub, .mi, .rm16, .imm16, .none, .none, 1, 0x81, 0x00, 0x00, 5 },
    .{ .sub, .mi, .rm32, .imm32, .none, .none, 1, 0x81, 0x00, 0x00, 5 },
    .{ .sub, .mi, .rm64, .imm32, .none, .none, 1, 0x81, 0x00, 0x00, 5 },
    .{ .sub, .mi, .rm16, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 5 },
    .{ .sub, .mi, .rm32, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 5 },
    .{ .sub, .mi, .rm64, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 5 },
    .{ .sub, .mr, .rm8, .r8, .none, .none, 1, 0x28, 0x00, 0x00, 0 },
    .{ .sub, .mr, .rm16, .r16, .none, .none, 1, 0x29, 0x00, 0x00, 0 },
    .{ .sub, .mr, .rm32, .r32, .none, .none, 1, 0x29, 0x00, 0x00, 0 },
    .{ .sub, .mr, .rm64, .r64, .none, .none, 1, 0x29, 0x00, 0x00, 0 },
    .{ .sub, .rm, .r8, .rm8, .none, .none, 1, 0x2a, 0x00, 0x00, 0 },
    .{ .sub, .rm, .r16, .rm16, .none, .none, 1, 0x2b, 0x00, 0x00, 0 },
    .{ .sub, .rm, .r32, .rm32, .none, .none, 1, 0x2b, 0x00, 0x00, 0 },
    .{ .sub, .rm, .r64, .rm64, .none, .none, 1, 0x2b, 0x00, 0x00, 0 },

    .{ .syscall, .np, .none, .none, .none, .none, 2, 0x0f, 0x05, 0x00, 0 },

    .{ .@"test", .zi, .al, .imm8, .none, .none, 1, 0xa8, 0x00, 0x00, 0 },
    .{ .@"test", .zi, .ax, .imm16, .none, .none, 1, 0xa9, 0x00, 0x00, 0 },
    .{ .@"test", .zi, .eax, .imm32, .none, .none, 1, 0xa9, 0x00, 0x00, 0 },
    .{ .@"test", .zi, .rax, .imm32, .none, .none, 1, 0xa9, 0x00, 0x00, 0 },
    .{ .@"test", .mi, .rm8, .imm8, .none, .none, 1, 0xf6, 0x00, 0x00, 0 },
    .{ .@"test", .mi, .rm16, .imm16, .none, .none, 1, 0xf7, 0x00, 0x00, 0 },
    .{ .@"test", .mi, .rm32, .imm32, .none, .none, 1, 0xf7, 0x00, 0x00, 0 },
    .{ .@"test", .mi, .rm64, .imm32, .none, .none, 1, 0xf7, 0x00, 0x00, 0 },
    .{ .@"test", .mr, .rm8, .r8, .none, .none, 1, 0x84, 0x00, 0x00, 0 },
    .{ .@"test", .mr, .rm16, .r16, .none, .none, 1, 0x85, 0x00, 0x00, 0 },
    .{ .@"test", .mr, .rm32, .r32, .none, .none, 1, 0x85, 0x00, 0x00, 0 },
    .{ .@"test", .mr, .rm64, .r64, .none, .none, 1, 0x85, 0x00, 0x00, 0 },

    .{ .xor, .zi, .al, .imm8, .none, .none, 1, 0x34, 0x00, 0x00, 0 },
    .{ .xor, .zi, .ax, .imm16, .none, .none, 1, 0x35, 0x00, 0x00, 0 },
    .{ .xor, .zi, .eax, .imm32, .none, .none, 1, 0x35, 0x00, 0x00, 0 },
    .{ .xor, .zi, .rax, .imm32, .none, .none, 1, 0x35, 0x00, 0x00, 0 },
    .{ .xor, .mi, .rm8, .imm8, .none, .none, 1, 0x80, 0x00, 0x00, 6 },
    .{ .xor, .mi, .rm16, .imm16, .none, .none, 1, 0x81, 0x00, 0x00, 6 },
    .{ .xor, .mi, .rm32, .imm32, .none, .none, 1, 0x81, 0x00, 0x00, 6 },
    .{ .xor, .mi, .rm64, .imm32, .none, .none, 1, 0x81, 0x00, 0x00, 6 },
    .{ .xor, .mi, .rm16, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 6 },
    .{ .xor, .mi, .rm32, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 6 },
    .{ .xor, .mi, .rm64, .imm8, .none, .none, 1, 0x83, 0x00, 0x00, 6 },
    .{ .xor, .mr, .rm8, .r8, .none, .none, 1, 0x30, 0x00, 0x00, 0 },
    .{ .xor, .mr, .rm16, .r16, .none, .none, 1, 0x31, 0x00, 0x00, 0 },
    .{ .xor, .mr, .rm32, .r32, .none, .none, 1, 0x31, 0x00, 0x00, 0 },
    .{ .xor, .mr, .rm64, .r64, .none, .none, 1, 0x31, 0x00, 0x00, 0 },
    .{ .xor, .rm, .r8, .rm8, .none, .none, 1, 0x32, 0x00, 0x00, 0 },
    .{ .xor, .rm, .r16, .rm16, .none, .none, 1, 0x33, 0x00, 0x00, 0 },
    .{ .xor, .rm, .r32, .rm32, .none, .none, 1, 0x33, 0x00, 0x00, 0 },
    .{ .xor, .rm, .r64, .rm64, .none, .none, 1, 0x33, 0x00, 0x00, 0 },
};
