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
                    'x', '0'...'9' => {}, // TODO validate there is only one '0x' pair within a numeral
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
    try as.skip(2, .{ .space, .new_line });
    const mnemonic_tok = as.expect(.string) catch |err| switch (err) {
        error.UnexpectedToken => return if (try as.peek() == .eof) null else err,
        else => return err,
    };
    const mnemonic = mnemonicFromString(as.source(mnemonic_tok)) orelse
        return error.InvalidMnemonic;
    try as.skip(1, .{.space});

    const rules = .{
        .{},
        .{.register},
        .{.memory},
        .{.immediate},
        .{ .register, .register },
        .{ .register, .memory },
        .{ .memory, .register },
        .{ .register, .immediate },
        .{ .memory, .immediate },
        .{ .register, .register, .immediate },
        .{ .register, .memory, .immediate },
    };

    const pos = as.it.pos;
    inline for (rules) |rule| {
        var ops = [4]Operand{ .none, .none, .none, .none };
        if (as.parseOperandRule(rule, &ops)) {
            return .{
                .mnemonic = mnemonic,
                .ops = ops,
            };
        } else |_| {
            as.it.seekTo(pos);
        }
    }

    return error.InvalidOperand;
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

fn parseOperandRule(as: *Assembler, rule: anytype, ops: *[4]Operand) ParseError!void {
    inline for (rule, 0..) |cond, i| {
        comptime assert(i < 4);
        if (i > 0) {
            _ = try as.expect(.comma);
            try as.skip(1, .{.space});
        }
        if (@typeInfo(@TypeOf(cond)) != .EnumLiteral) {
            @compileError("invalid condition in the rule: " ++ @typeName(@TypeOf(cond)));
        }
        switch (cond) {
            .register => {
                const reg_tok = try as.expect(.string);
                const reg = registerFromString(as.source(reg_tok)) orelse
                    return error.InvalidOperand;
                ops[i] = .{ .reg = reg };
            },
            .memory => {
                const mem = try as.parseMemory();
                ops[i] = .{ .mem = mem };
            },
            .immediate => {
                const imm_tok = try as.expect(.numeral);
                const imm = try std.fmt.parseInt(u64, as.source(imm_tok), 0);
                ops[i] = .{ .imm = @bitCast(i64, imm) };
            },
            else => @compileError("unhandled enum literal " ++ @tagName(cond)),
        }
        try as.skip(1, .{.space});
    }

    try as.skip(1, .{.space});
    const tok = try as.it.next();
    switch (tok.id) {
        .new_line, .eof => {},
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

fn parseMemory(as: *Assembler) ParseError!Memory {
    const ptr_size: ?Memory.PtrSize = blk: {
        const pos = as.it.pos;
        const ptr_size = as.parsePtrSize() catch |err| switch (err) {
            error.UnexpectedToken => {
                as.it.seekTo(pos);
                break :blk null;
            },
            else => return err,
        };
        break :blk ptr_size;
    };

    try as.skip(1, .{.space});

    // Supported rules and orderings.
    const rules = .{
        .{ .open_br, .base, .close_br }, // [ base ]
        .{ .open_br, .base, .plus, .disp, .close_br }, // [ base + disp ]
        .{ .open_br, .base, .minus, .disp, .close_br }, // [ base - disp ]
        .{ .open_br, .disp, .plus, .base, .close_br }, // [ disp + base ]
        .{ .open_br, .base, .plus, .index, .close_br }, // [ base + index ]
        .{ .open_br, .base, .plus, .index, .star, .scale, .close_br }, // [ base + index * scale ]
        .{ .open_br, .index, .star, .scale, .plus, .base, .close_br }, // [ index * scale + base ]
        .{ .open_br, .base, .plus, .index, .star, .scale, .plus, .disp, .close_br }, // [ base + index * scale + disp ]
        .{ .open_br, .base, .plus, .index, .star, .scale, .minus, .disp, .close_br }, // [ base + index * scale - disp ]
        .{ .open_br, .index, .star, .scale, .plus, .base, .plus, .disp, .close_br }, // [ index * scale + base + disp ]
        .{ .open_br, .index, .star, .scale, .plus, .base, .minus, .disp, .close_br }, // [ index * scale + base - disp ]
        .{ .open_br, .disp, .plus, .index, .star, .scale, .plus, .base, .close_br }, // [ disp + index * scale + base ]
        .{ .open_br, .disp, .plus, .base, .plus, .index, .star, .scale, .close_br }, // [ disp + base + index * scale ]
        .{ .open_br, .base, .plus, .disp, .plus, .index, .star, .scale, .close_br }, // [ base + disp + index * scale ]
        .{ .open_br, .base, .minus, .disp, .plus, .index, .star, .scale, .close_br }, // [ base - disp + index * scale ]
        .{ .open_br, .base, .plus, .disp, .plus, .scale, .star, .index, .close_br }, // [ base + disp + scale * index ]
        .{ .open_br, .base, .minus, .disp, .plus, .scale, .star, .index, .close_br }, // [ base - disp + scale * index ]
        .{ .open_br, .rip, .plus, .disp, .close_br }, // [ rip + disp ]
        .{ .open_br, .rip, .minus, .disp, .close_br }, // [ rig - disp ]
        .{ .base, .colon, .disp }, // seg:disp
    };

    const pos = as.it.pos;
    inline for (rules) |rule| {
        if (as.parseMemoryRule(rule)) |res| {
            if (res.rip) {
                if (res.base != null or res.scale_index != null or res.offset != null)
                    return error.InvalidMemoryOperand;
                return Memory.rip(ptr_size orelse .qword, res.disp orelse 0);
            }
            if (res.base) |base| {
                if (res.rip)
                    return error.InvalidMemoryOperand;
                if (res.offset) |offset| {
                    if (res.scale_index != null or res.disp != null)
                        return error.InvalidMemoryOperand;
                    return Memory.moffs(base, offset);
                }
                return Memory.sib(ptr_size orelse .qword, .{
                    .base = base,
                    .scale_index = res.scale_index,
                    .disp = res.disp orelse 0,
                });
            }
            return error.InvalidMemoryOperand;
        } else |_| {
            as.it.seekTo(pos);
        }
    }

    return error.InvalidOperand;
}

const MemoryParseResult = struct {
    rip: bool = false,
    base: ?Register = null,
    scale_index: ?Memory.ScaleIndex = null,
    disp: ?i32 = null,
    offset: ?u64 = null,
};

fn parseMemoryRule(as: *Assembler, rule: anytype) ParseError!MemoryParseResult {
    var res: MemoryParseResult = .{};
    inline for (rule, 0..) |cond, i| {
        if (@typeInfo(@TypeOf(cond)) != .EnumLiteral) {
            @compileError("unsupported condition type in the rule: " ++ @typeName(@TypeOf(cond)));
        }
        switch (cond) {
            .open_br, .close_br, .plus, .minus, .star, .colon => {
                _ = try as.expect(cond);
            },
            .base => {
                const tok = try as.expect(.string);
                res.base = registerFromString(as.source(tok)) orelse return error.InvalidMemoryOperand;
            },
            .rip => {
                const tok = try as.expect(.string);
                if (!std.mem.eql(u8, as.source(tok), "rip")) return error.InvalidMemoryOperand;
                res.rip = true;
            },
            .index => {
                const tok = try as.expect(.string);
                const index = registerFromString(as.source(tok)) orelse
                    return error.InvalidMemoryOperand;
                if (res.scale_index) |*si| {
                    si.index = index;
                } else {
                    res.scale_index = .{ .scale = 1, .index = index };
                }
            },
            .scale => {
                const tok = try as.expect(.numeral);
                const scale = try std.fmt.parseInt(u2, as.source(tok), 0);
                if (res.scale_index) |*si| {
                    si.scale = scale;
                } else {
                    res.scale_index = .{ .scale = scale, .index = undefined };
                }
            },
            .disp => {
                const tok = try as.expect(.numeral);
                const is_neg = blk: {
                    if (i > 0) {
                        if (rule[i - 1] == .minus) break :blk true;
                    }
                    break :blk false;
                };
                if (std.fmt.parseInt(i32, as.source(tok), 0)) |disp| {
                    res.disp = if (is_neg) -1 * disp else disp;
                } else |err| switch (err) {
                    error.Overflow => {
                        if (is_neg) return err;
                        if (res.base) |base| {
                            if (base.class() != .segment) return err;
                        }
                        const offset = try std.fmt.parseInt(u64, as.source(tok), 0);
                        res.offset = offset;
                    },
                    else => return err,
                }
            },
            else => @compileError("unhandled operand output type: " ++ @tagName(cond)),
        }
        try as.skip(1, .{.space});
    }
    return res;
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
