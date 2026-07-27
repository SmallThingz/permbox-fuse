const std = @import("std");
const Trie = @import("trie.zig");

pub const Mode = Trie.Mode;
pub const Error = error{
    InvalidSyntax,
    InvalidPath,
    InvalidFlag,
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

/// Parse the permbox `fs` rule syntax. Both flat canonical entries and nested
/// entries are accepted. Later entries for the same path are left for the trie
/// insertion layer to replace.
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
        if (!validPath(rule.path))
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
                const escaped = std.fmt.bufPrint(&buf, "\\x{x:0>2}", .{byte}) catch unreachable;
                try out.appendSlice(allocator, escaped);
            } else try out.append(allocator, byte),
        };
        try out.appendSlice(allocator, "\":");
        try appendMode(allocator, &out, rule.mode);
        try out.appendSlice(allocator, "\n");
    }
    try out.appendSlice(allocator, "}\n");
    return out.toOwnedSlice(allocator) catch error.OutOfMemory;
}

fn appendMode(allocator: std.mem.Allocator, out: *std.ArrayList(u8), mode: Mode) Error!void {
    try out.appendSlice(allocator, switch (mode.k) {
        .visible_raw => "access",
        .visible_virtual => "empty",
        .invisible => "no-access",
        .midway => return error.InvalidMode,
    });
    try appendAccess(allocator, out, mode.r, "r");
    try out.append(allocator, ',');
    try out.appendSlice(allocator, switch (mode.w) {
        .deny => "deny-w",
        .ask => "allow-w",
        .allow => "ALWAYS-allow-w",
        .overlay => "overlay-w",
    });
    try appendAccess(allocator, out, mode.x, "x");
}

fn appendAccess(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: Mode.A, suffix: []const u8) Error!void {
    try out.append(allocator, ',');
    try out.appendSlice(allocator, switch (value) {
        .deny => "deny-",
        .ask => "allow-",
        .allow => "ALWAYS-allow-",
        ._reserved => return error.InvalidMode,
    });
    try out.appendSlice(allocator, suffix);
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
            self.skipSpaceAndSeparators();
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
            const flags_start = self.index;
            while (self.index < self.text.len) : (self.index += 1) switch (self.text[self.index]) {
                '{', '}', ';', '"', '#', '\n' => break,
                else => {},
            };
            const flags = std.mem.trim(u8, self.text[flags_start..self.index], " \t\r,");
            const path = try joinPath(self.allocator, parent, key);
            errdefer self.allocator.free(path);
            const mode = try parseMode(flags);
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
                    const value = std.fmt.parseInt(u8, self.text[self.index .. self.index + 2], 16) catch
                        return error.InvalidSyntax;
                    self.index += 2;
                    try out.append(self.allocator, value);
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
                continue;
            }
            if (self.text[self.index] != '#') return;
            while (self.index < self.text.len and self.text[self.index] != '\n')
                self.index += 1;
        }
    }

    fn skipSpaceAndSeparators(self: *Parser) void {
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
        if (self.index >= self.text.len or self.text[self.index] != byte) return false;
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
    const separator = if (parent.len == 1) "" else "/";
    const path = std.fmt.allocPrint(allocator, "{s}{s}{s}", .{
        parent,
        separator,
        key,
    }) catch return error.OutOfMemory;
    if (!validPath(path)) {
        allocator.free(path);
        return error.InvalidPath;
    }
    return path;
}

fn validPath(path: []const u8) bool {
    if (path.len == 0 or path[0] != '/' or
        std.mem.indexOfScalar(u8, path, 0) != null)
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

pub fn parseMode(flags: []const u8) Error!Mode {
    var mode = Mode.dir;
    var tokens = std.mem.splitScalar(u8, flags, ',');
    while (tokens.next()) |raw| {
        const token = std.mem.trim(u8, raw, " \t\r\n");
        if (token.len == 0) continue;
        if (std.mem.eql(u8, token, "access")) mode.k = .visible_raw else if (std.mem.eql(u8, token, "empty")) mode.k = .visible_virtual else if (std.mem.eql(u8, token, "no-access")) mode.k = .invisible else if (std.mem.eql(u8, token, "overlay-w")) mode.w = .overlay else if (std.mem.startsWith(u8, token, "deny-"))
            try setPermissions(&mode, token[5..], .deny)
        else if (std.mem.startsWith(u8, token, "allow-"))
            try setPermissions(&mode, token[6..], .ask)
        else if (std.mem.startsWith(u8, token, "ALWAYS-allow-") or
            std.mem.startsWith(u8, token, "always-allow-"))
        {
            const prefix_len: usize = if (token[0] == 'A') 13 else 13;
            try setPermissions(&mode, token[prefix_len..], .allow);
        } else return error.InvalidFlag;
    }
    return mode;
}

fn setPermissions(mode: *Mode, bits: []const u8, access: Mode.A) Error!void {
    if (bits.len == 0) return error.InvalidFlag;
    for (bits) |bit| switch (bit) {
        'r' => mode.r = access,
        'x' => mode.x = access,
        'w' => mode.w = switch (access) {
            .deny => .deny,
            .ask => .ask,
            .allow => .allow,
            ._reserved => unreachable,
        },
        else => return error.InvalidFlag,
    };
}
