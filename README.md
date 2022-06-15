# zig-dis-x86_64
x86_64 disassembler library written in Zig

## What is it?

You can use this library to disassemble and encode x86_64 machine code.

## Why is it?

I needed a simple disassembler for linker optimisations in `zig ld` for x86_64.

## Basic usage

Disassembling input byte buffer:

```zig
const std = @import("std");
const Disassembler = @import("dis_x86_64").Disassembler;

var disassembler = Disassembler.init(&.{
    0x40, 0xb7, 0x10,  // mov dil, 0x10
    0x48, 0x8b, 0xd8,  // mov rbx, rax
});

var text = std.ArrayList(u8).init(gpa);
defer text.deinit();

while (try disassembler.next()) |inst| {
    try inst.fmtPrint(text.writer());
    try text.append('\n');
}

try std.testing.expectEqualStrings(
    \\mov dil, 0x10
    \\mov rbx, rax
, text.items);
```

Encoding instructions back to machine code:

```zig
const std = @import("std");
const Instruction = @import("dis_x86_64").Instruction;
const RegisterOrMemory = @import("dis_x86_64").RegisterOrMemory;

var code = std.ArrayList(u8).init(gpa);
defer code.deinit();

const inst = Instruction{
    .tag = .mov,
    .enc = .mi,
    .data = Instruction.Data.mi(RegisterOrMemory.reg(.rbx), 0x4),
};
try inst.encode(code.writer());

try std.testing.expectEqualSlices(u8, "\x48\xc7\xc3\x04\x00\x00\x00", code.items);
```
