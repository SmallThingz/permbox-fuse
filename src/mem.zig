// The MIT License (Expat)
//
// Copyright (c) Zig contributors
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

const std = @import("std");
const builtin = @import("builtin");
const testing = std.testing;

const use_vectors = switch (builtin.zig_backend) {
    // These backends don't support vectors yet.
    .stage2_aarch64,
    .stage2_powerpc,
    .stage2_riscv64,
    => false,
    // The SPIR-V backend does not support the optimized path yet.
    .stage2_spirv => false,
    else => true,
};

// The naive memory comparison implementation is more useful for fuzzers to find interesting inputs.
const use_vectors_for_comparison = use_vectors and !builtin.fuzz;

/// Returns true if and only if the slices have the same length and all elements
/// compare true using equality operator.
pub fn findDiff(comptime T: type, a: []const T, b: []const T) ?usize {
    const minlen = @min(a.len, b.len);
    var i: usize = 0;
    if (use_vectors_for_comparison and
        !std.debug.inValgrind() and // https://github.com/ziglang/zig/issues/17717
        !@inComptime() and
        (@typeInfo(T) == .int or @typeInfo(T) == .float) and std.math.isPowerOfTwo(@bitSizeOf(T)))
    {
        if (std.simd.suggestVectorLength(T)) |block_len| {
            const Block = @Vector(block_len, T);
            while (i + 2 * block_len <= minlen) : (i += block_len) {
                inline for (0..2) |_| {
                    const blocka: Block = a[i..][0..block_len].*;
                    const blockb: Block = b[i..][0..block_len].*;
                    const matches = blocka == blockb;
                    if (@reduce(.Or, matches)) return i + std.simd.firstTrue(matches).?;
                }
            }

            // {block_len, block_len / 2} check
            inline for (0..2) |j| {
                const block_x_len = block_len / (1 << j);
                comptime if (block_x_len < 4) break;

                const BlockX = @Vector(block_x_len, T);
                if (i + block_x_len <= minlen) {
                    const blocka: BlockX = a[i..][0..block_x_len].*;
                    const blockb: BlockX = b[i..][0..block_x_len].*;
                    const matches = blocka == blockb;
                    if (@reduce(.Or, matches)) return i + std.simd.firstTrue(matches).?;
                    i += block_x_len;
                }
            }
        }
    }

    while (i < minlen) : (i += 1) if (a[i] != b[i]) return i;
    return if (a.len == b.len) null else minlen;
}
