const Assembler = @This();

const std = @import("std");
const assert = std.debug.assert;
const bits = @import("bits.zig");
const encoder = @import("encoder.zig");

const Instruction = encoder.Instruction;
const Memory = bits.Memory;
const Mnemonic = Instruction.Mnemonic;
const Moffs = bits.Moffs;
const Operand = Instruction.Operand;
const Register = bits.Register;

it: Tokenizer,

const Tokenizer = struct {
    input: []const u8,
    pos: usize = 0,

    const Error = error{InvalidToken};

    const Token = struct {
        id: Id,
        start: usize,
        end: usize,

        const Id = enum {
            eof,

            space,
            new_line,

            colon,
            comma,
            open_br,
            close_br,
            plus,
            minus,
            star,

            string,
            numeral,
        };
    };

    const Iterator = struct {};

    fn next(it: *Tokenizer) !Token {
        var result = Token{
            .id = .eof,
            .start = it.pos,
            .end = it.pos,
        };

        var state: enum {
            start,
            space,
            new_line,
            string,
            numeral,
        } = .start;

        while (it.pos < it.input.len) : (it.pos += 1) {
            const ch = it.input[it.pos];
            switch (state) {
                .start => switch (ch) {
                    ',' => {
                        result.id = .comma;
                        it.pos += 1;
                        break;
                    },
                    ':' => {
                        result.id = .colon;
                        it.pos += 1;
                        break;
                    },
                    '[' => {
                        result.id = .open_br;
                        it.pos += 1;
                        break;
                    },
                    ']' => {
                        result.id = .close_br;
                        it.pos += 1;
                        break;
                    },
                    '+' => {
                        result.id = .plus;
                        it.pos += 1;
                        break;
                    },
                    '-' => {
                        result.id = .minus;
                        it.pos += 1;
                        break;
                    },
                    '*' => {
                        result.id = .star;
                        it.pos += 1;
                        break;
                    },
                    ' ', '\t' => state = .space,
                    '\n', '\r' => state = .new_line,
                    'a'...'z', 'A'...'Z' => state = .string,
                    '0'...'9' => state = .numeral,
                    else => return error.InvalidToken,
                },

                .space => switch (ch) {
                    ' ', '\t' => {},
                    else => {
                        result.id = .space;
                        break;
                    },
                },

                .new_line => switch (ch) {
                    '\n', '\r', ' ', '\t' => {},
                    else => {
                        result.id = .new_line;
                        break;
                    },
                },

                .string => switch (ch) {
                    'a'...'z', 'A'...'Z', '0'...'9' => {},
                    else => {
                        result.id = .string;
                        break;
                    },
                },

                .numeral => switch (ch) {
                    '0'...'9' => {},
                    else => {
                        result.id = .numeral;
                        break;
                    },
                },
            }
        }

        if (it.pos >= it.input.len) {
            switch (state) {
                .string => result.id = .string,
                .numeral => result.id = .numeral,
                else => {},
            }
        }

        result.end = it.pos;
        return result;
    }

    fn seekTo(it: *Tokenizer, pos: usize) void {
        it.pos = pos;
    }
};

pub fn init(input: []const u8) Assembler {
    return .{
        .it = Tokenizer{ .input = input },
    };
}

pub fn assemble(as: *Assembler, writer: anytype) !void {
    while (try as.next()) |parsed_inst| {
        const inst = try Instruction.new(.{
            .mnemonic = parsed_inst.mnemonic,
            .op1 = parsed_inst.ops[0],
            .op2 = parsed_inst.ops[1],
            .op3 = parsed_inst.ops[2],
            .op4 = parsed_inst.ops[3],
        });
        try inst.encode(writer);
    }
}

const ParseResult = struct {
    mnemonic: Mnemonic,
    ops: [4]Operand,
};

const ParseError = error{
    UnexpectedToken,
    InvalidMnemonic,
    InvalidOperand,
    InvalidRegister,
    InvalidPtrSize,
    InvalidMemoryOperand,
    InvalidScaleIndex,
} || Tokenizer.Error || std.fmt.ParseIntError;

fn next(as: *Assembler) ParseError!?ParseResult {
    var result = ParseResult{
        .mnemonic = undefined,
        .ops = .{ .none, .none, .none, .none },
    };

    try as.skip(2, .{ .space, .new_line });
    const mnemonic = as.expect(.string) catch |err| switch (err) {
        error.UnexpectedToken => return if (try as.peek() == .eof) null else err,
        else => return err,
    };
    result.mnemonic = mnemonicFromString(as.source(mnemonic)) orelse return error.InvalidMnemonic;

    inline for (&result.ops, 0..) |*op, i| {
        if (i > 0) {
            try as.skip(1, .{.space});
            _ = as.expect(.comma) catch |err| switch (err) {
                error.UnexpectedToken => switch (try as.peek()) {
                    .new_line, .eof => break,
                    else => return err,
                },
                else => return err,
            };
        }
        try as.skip(1, .{.space});
        op.* = as.parseOperand() catch |err| switch (err) {
            error.InvalidOperand => switch (try as.peek()) {
                .new_line, .eof => break,
                else => return err,
            },
            else => return err,
        };
    }

    return result;
}

fn source(as: *Assembler, token: Tokenizer.Token) []const u8 {
    return as.it.input[token.start..token.end];
}

fn peek(as: *Assembler) Tokenizer.Error!Tokenizer.Token.Id {
    const pos = as.it.pos;
    const next_tok = try as.it.next();
    const id = next_tok.id;
    as.it.seekTo(pos);
    return id;
}

fn expect(as: *Assembler, id: Tokenizer.Token.Id) ParseError!Tokenizer.Token {
    const next_tok_id = try as.peek();
    if (next_tok_id == id) return as.it.next();
    return error.UnexpectedToken;
}

fn skip(as: *Assembler, comptime num: comptime_int, tok_ids: [num]Tokenizer.Token.Id) Tokenizer.Error!void {
    outer: while (true) {
        const pos = as.it.pos;
        const next_tok = try as.it.next();
        inline for (tok_ids) |tok_id| {
            if (next_tok.id == tok_id) continue :outer;
        }
        as.it.seekTo(pos);
        break;
    }
}

fn mnemonicFromString(bytes: []const u8) ?Mnemonic {
    const ti = @typeInfo(Mnemonic).Enum;
    inline for (ti.fields) |field| {
        if (std.mem.eql(u8, bytes, field.name)) {
            return @field(Mnemonic, field.name);
        }
    }
    return null;
}

fn parseOperand(as: *Assembler) ParseError!Operand {
    err: {
        const pos = as.it.pos;
        const reg = as.parseRegister() catch {
            as.it.seekTo(pos);
            break :err;
        };
        return .{ .reg = reg };
    }

    err: {
        const pos = as.it.pos;
        const mem = as.parseMemory() catch {
            as.it.seekTo(pos);
            break :err;
        };
        return .{ .mem = mem };
    }

    return error.InvalidOperand;
}

fn parseRegister(as: *Assembler) ParseError!Register {
    const string = try as.expect(.string);
    const reg = registerFromString(as.source(string)) orelse return error.InvalidOperand;
    try as.skip(1, .{.space});
    switch (try as.peek()) {
        .eof, .new_line, .comma => return reg,
        else => return error.InvalidOperand,
    }
}

fn registerFromString(bytes: []const u8) ?Register {
    const ti = @typeInfo(Register).Enum;
    inline for (ti.fields) |field| {
        if (std.mem.eql(u8, bytes, field.name)) {
            return @field(Register, field.name);
        }
    }
    return null;
}

const Pair = std.meta.Tuple(&.{ Tokenizer.Token.Id, ?[]const u8 });
const Rule = []const Pair;

const memory_rules = &[_]Rule{
    &.{
        .{ .open_br, null },
        .{ .string, "base" },
        .{ .close_br, null },
    },
    &.{
        .{ .open_br, null },
        .{ .string, "base" },
        .{ .plus, null },
        .{ .numeral, "disp" },
        .{ .close_br, null },
    },
    &.{
        .{ .open_br, null },
        .{ .string, "base" },
        .{ .minus, null },
        .{ .numeral, "disp" },
        .{ .close_br, null },
    },
    &.{
        .{ .open_br, null },
        .{ .numeral, "disp" },
        .{ .plus, null },
        .{ .string, "base" },
        .{ .close_br, null },
    },
    &.{
        .{ .open_br, null },
        .{ .numeral, "disp" },
        .{ .minus, null },
        .{ .string, "base" },
        .{ .close_br, null },
    },
};

fn parseMemory(as: *Assembler) ParseError!Memory {
    var mem = Memory{
        .base = null,
        .ptr_size = undefined,
        .disp = 0,
    };
    mem.ptr_size = as.parsePtrSize() catch |err| switch (err) {
        error.UnexpectedToken => .qword,
        else => return err,
    };

    try as.skip(1, .{.space});

    const pos = as.it.pos;
    inline for (memory_rules) |rule| {
        if (as.parseMemoryRule(rule, &mem)) {
            return mem;
        } else |_| {
            as.it.seekTo(pos);
        }
    }

    return error.InvalidOperand;
}

fn parseMemoryRule(as: *Assembler, comptime rule: Rule, mem: *Memory) ParseError!void {
    inline for (rule, 0..) |pair, i| {
        const tok = try as.expect(pair[0]);
        try as.skip(1, .{.space});

        if (pair[1]) |field_name| {
            if (std.mem.eql(u8, field_name, "base")) {
                @field(mem, "base") = registerFromString(as.source(tok)) orelse return error.InvalidMemoryOperand;
            }
            if (std.mem.eql(u8, field_name, "disp")) {
                const is_neg = blk: {
                    if (i > 0) {
                        if (rule[i - 1][0] == .minus) break :blk true;
                    }
                    break :blk false;
                };
                var disp = try std.fmt.parseInt(i32, as.source(tok), 0);
                if (is_neg) {
                    disp *= -1;
                }
                @field(mem, "disp") = disp;
            }
        }
    }
    switch (try as.peek()) {
        .eof, .new_line, .comma => {},
        else => return error.InvalidMemoryOperand,
    }
}

fn parsePtrSize(as: *Assembler) ParseError!Memory.PtrSize {
    const size = try as.expect(.string);
    try as.skip(1, .{.space});
    const ptr = try as.expect(.string);

    const size_raw = as.source(size);
    const ptr_raw = as.source(ptr);
    const len = size_raw.len + ptr_raw.len + 1;
    var buf: ["qword ptr".len]u8 = undefined;
    if (len > buf.len) return error.InvalidPtrSize;

    for (size_raw, 0..) |c, i| {
        buf[i] = std.ascii.toLower(c);
    }
    buf[size_raw.len] = ' ';
    for (ptr_raw, 0..) |c, i| {
        buf[size_raw.len + i + 1] = std.ascii.toLower(c);
    }

    const slice = buf[0..len];
    if (std.mem.eql(u8, slice, "qword ptr")) return .qword;
    if (std.mem.eql(u8, slice, "dword ptr")) return .dword;
    if (std.mem.eql(u8, slice, "word ptr")) return .word;
    if (std.mem.eql(u8, slice, "byte ptr")) return .byte;
    return error.InvalidPtrSize;
}
