const std = @import("std");
const Trie = @import("trie.zig");

pub const Mode = Trie.Mode;
pub const Error = error{
    InvalidSyntax,
    InvalidPath,
    InvalidMode,
    OutOfMemory,
};

pub const ParsedRule = struct {
    path: []u8,
    mode: Mode,
};

pub fn freeRules(allocator: std.mem.Allocator, rules: []ParsedRule) void {
    for (rules) |rule| allocator.free(rule.path);
    allocator.free(rules);
}

pub fn parseMode(text: []const u8) Error!Mode {
    const value = std.mem.trim(u8, text, " \t\r\n,");
    inline for (.{ Mode.whiteout, Mode.r, Mode.rw, Mode.ask }) |mode| {
        if (std.mem.eql(u8, value, @tagName(mode))) return mode;
    }
    return error.InvalidMode;
}

pub fn parse(allocator: std.mem.Allocator, text: []const u8) Error![]ParsedRule {
    var parser = Parser{ .allocator = allocator, .text = text };
    errdefer parser.deinit();
    parser.skipSpace();
    if (parser.consumeWord("fs")) {
        parser.skipSpace();
        try parser.expect('{');
        try parser.parseEntries("", '}');
    } else {
        try parser.parseEntries("", null);
    }
    parser.skipSpace();
    if (parser.index != text.len) return error.InvalidSyntax;
    return parser.rules.toOwnedSlice(allocator) catch error.OutOfMemory;
}

pub fn format(allocator: std.mem.Allocator, rules: []const Trie.Rule) Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, "fs {\n");
    for (rules) |rule| {
        if (!validPath(rule.path) or rule.mode == .midway)
            return error.InvalidPath;
        try out.appendSlice(allocator, "  \"");
        for (rule.path) |byte| switch (byte) {
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '"' => try out.appendSlice(allocator, "\\\""),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            else => if (std.ascii.isControl(byte)) {
                var buf: [4]u8 = undefined;
                try out.appendSlice(allocator, std.fmt.bufPrint(&buf, "\\x{x:0>2}", .{byte}) catch unreachable);
            } else try out.append(allocator, byte),
        };
        try out.appendSlice(allocator, "\":");
        try out.appendSlice(allocator, @tagName(rule.mode));
        try out.append(allocator, '\n');
    }
    try out.appendSlice(allocator, "}\n");
    return out.toOwnedSlice(allocator) catch error.OutOfMemory;
}

const Parser = struct {
    allocator: std.mem.Allocator,
    text: []const u8,
    index: usize = 0,
    rules: std.ArrayList(ParsedRule) = .empty,

    fn deinit(self: *Parser) void {
        for (self.rules.items) |rule| self.allocator.free(rule.path);
        self.rules.deinit(self.allocator);
    }

    fn parseEntries(self: *Parser, parent: []const u8, end: ?u8) Error!void {
        while (true) {
            self.skipSeparators();
            if (self.index == self.text.len)
                return if (end == null) {} else error.InvalidSyntax;
            if (end) |closing| if (self.text[self.index] == closing) {
                self.index += 1;
                return;
            };

            const key = try self.parseQuoted();
            defer self.allocator.free(key);
            self.skipSpace();
            if (self.consume(':')) self.skipSpace();
            const start = self.index;
            while (self.index < self.text.len) : (self.index += 1) switch (self.text[self.index]) {
                '{', '}', ';', '#', '\n' => break,
                else => {},
            };
            const mode = try parseMode(self.text[start..self.index]);
            const path = try joinPath(self.allocator, parent, key);
            errdefer self.allocator.free(path);
            try self.rules.append(self.allocator, .{ .path = path, .mode = mode });
            self.skipSpace();
            if (self.consume('{')) try self.parseEntries(path, '}');
            self.skipSpace();
            _ = self.consume(';');
        }
    }

    fn parseQuoted(self: *Parser) Error![]u8 {
        if (!self.consume('"')) return error.InvalidSyntax;
        var out: std.ArrayList(u8) = .empty;
        errdefer out.deinit(self.allocator);
        while (self.index < self.text.len) {
            const byte = self.text[self.index];
            self.index += 1;
            if (byte == '"') return out.toOwnedSlice(self.allocator) catch error.OutOfMemory;
            if (byte != '\\') {
                try out.append(self.allocator, byte);
                continue;
            }
            if (self.index == self.text.len) return error.InvalidSyntax;
            const escaped = self.text[self.index];
            self.index += 1;
            switch (escaped) {
                '\\', '"' => try out.append(self.allocator, escaped),
                'n' => try out.append(self.allocator, '\n'),
                'r' => try out.append(self.allocator, '\r'),
                't' => try out.append(self.allocator, '\t'),
                'x' => {
                    if (self.index + 2 > self.text.len) return error.InvalidSyntax;
                    try out.append(self.allocator, std.fmt.parseInt(
                        u8,
                        self.text[self.index..][0..2],
                        16,
                    ) catch return error.InvalidSyntax);
                    self.index += 2;
                },
                else => return error.InvalidSyntax,
            }
        }
        return error.InvalidSyntax;
    }

    fn skipSpace(self: *Parser) void {
        while (self.index < self.text.len) {
            if (std.ascii.isWhitespace(self.text[self.index])) {
                self.index += 1;
            } else if (self.text[self.index] == '#') {
                while (self.index < self.text.len and self.text[self.index] != '\n')
                    self.index += 1;
            } else return;
        }
    }

    fn skipSeparators(self: *Parser) void {
        while (self.index < self.text.len) switch (self.text[self.index]) {
            ' ', '\t', '\r', '\n', ';' => self.index += 1,
            '#' => {
                while (self.index < self.text.len and self.text[self.index] != '\n')
                    self.index += 1;
            },
            else => return,
        };
    }

    fn consume(self: *Parser, byte: u8) bool {
        if (self.index == self.text.len or self.text[self.index] != byte) return false;
        self.index += 1;
        return true;
    }

    fn consumeWord(self: *Parser, word: []const u8) bool {
        if (!std.mem.startsWith(u8, self.text[self.index..], word)) return false;
        const end = self.index + word.len;
        if (end < self.text.len and (std.ascii.isAlphanumeric(self.text[end]) or self.text[end] == '_'))
            return false;
        self.index = end;
        return true;
    }

    fn expect(self: *Parser, byte: u8) Error!void {
        if (!self.consume(byte)) return error.InvalidSyntax;
    }
};

fn joinPath(allocator: std.mem.Allocator, parent: []const u8, key: []const u8) Error![]u8 {
    if (parent.len == 0) {
        if (!validPath(key)) return error.InvalidPath;
        return allocator.dupe(u8, key) catch error.OutOfMemory;
    }
    if (key.len == 0 or key[0] == '/') return error.InvalidPath;
    const path = std.fmt.allocPrint(
        allocator,
        "{s}{s}{s}",
        .{ parent, if (parent.len == 1) "" else "/", key },
    ) catch return error.OutOfMemory;
    if (!validPath(path)) {
        allocator.free(path);
        return error.InvalidPath;
    }
    return path;
}

fn validPath(path: []const u8) bool {
    if (path.len == 0 or path[0] != '/' or std.mem.indexOfScalar(u8, path, 0) != null)
        return false;
    if (path.len == 1) return true;
    if (path[path.len - 1] == '/') return false;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
            return false;
    }
    return true;
}

test "four policy states round trip" {
    const rules = [_]Trie.Rule{
        .{ .path = @constCast("/"), .mode = .rw },
        .{ .path = @constCast("/secret"), .mode = .whiteout },
        .{ .path = @constCast("/read"), .mode = .r },
        .{ .path = @constCast("/prompt"), .mode = .ask },
    };
    const text = try format(std.testing.allocator, &rules);
    defer std.testing.allocator.free(text);
    const parsed = try parse(std.testing.allocator, text);
    defer freeRules(std.testing.allocator, parsed);
    try std.testing.expectEqual(rules.len, parsed.len);
    for (rules, parsed) |expected, actual| {
        try std.testing.expectEqualStrings(expected.path, actual.path);
        try std.testing.expectEqual(expected.mode, actual.mode);
    }
}
