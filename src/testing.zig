const std = @import("std");
const builtin = @import("builtin");

const is_test = builtin.is_test;
const assert = std.debug.assert;
const io = std.testing.io;

pub const Lock = struct {
    state: State = if (is_test) .unlocked else {},

    pub const State = if (is_test) std.atomic.Value(enum { unlocked, locked }) else void;

    pub fn lock(l: *@This()) void {
        if (!is_test) return;
        assert(l.state.swap(.locked, .monotonic) == .unlocked);
    }

    pub fn unlock(l: *@This()) void {
        if (!is_test) return;
        assert(l.state.swap(.unlocked, .monotonic) == .locked);
    }

    pub fn assertUnlocked(l: @This()) void {
        if (!is_test) return;
        assert(l.state.load(.monotonic) == .unlocked);
    }

    pub fn assertLocked(l: @This()) void {
        if (!is_test) return;
        assert(l.state.load(.monotonic) == .locked);
    }
};

pub const Mutex = struct {
    state: if (is_test) std.Io.Mutex else void,

    pub const State = std.Io.Mutex.State;

    pub fn tryLock(m: *@This()) bool {
        if (!is_test) return true;
        return m.state.cmpxchgStrong(.unlocked, .locked_once, .acquire, .monotonic) == null;
    }

    pub fn lock(m: *Mutex) void {
        if (!is_test) return;
        const initial_state = m.state.cmpxchgStrong(
            .unlocked,
            .locked_once,
            .acquire,
            .monotonic,
        ) orelse {
            @branchHint(.likely);
            return;
        };
        if (initial_state == .contended) {
            io.futexWaitUncancelable(State, &m.state.raw, .contended);
        }
        while (m.state.swap(.contended, .acquire) != .unlocked) {
            io.futexWaitUncancelable(State, &m.state.raw, .contended);
        }
    }

    pub fn unlock(m: *Mutex) void {
        if (!is_test) return;
        switch (m.state.swap(.unlocked, .release)) {
            .unlocked => unreachable,
            .locked_once => {},
            .contended => {
                @branchHint(.unlikely);
                io.futexWake(State, &m.state.raw, 1);
            },
        }
    }
};
