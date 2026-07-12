//! This has the implementation of the trie that tracks the permissions
const std = @import("std");

const Mode = packed struct(u8) {
    access: bool,
    r: R,
    w: W,
    x: X,

    pub const R = enum(u2) {
        empty = 0,
        deny = 1,
        ask = 2,
        allow = 3,
    };
    pub const W = enum(u2) {
        overlay = 0,
        deny = 1,
        ask = 2,
        allow = 3,
    };
    pub const X = enum(u2) {
        default = 0,
        deny = 1,
        ask = 2,
        allow = 3,
    };
};

const Slab = struct {};
