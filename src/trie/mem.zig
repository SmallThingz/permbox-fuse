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
    const shortest = @min(a.len, b.len);
    var index: usize = 0;
    if (use_vectors_for_comparison and
        !std.debug.inValgrind() and
        !@inComptime() and
        (@typeInfo(T) == .int or @typeInfo(T) == .float) and std.math.isPowerOfTwo(@bitSizeOf(T)))
    {
        if (std.simd.suggestVectorLength(T)) |suggested_len| {
            const max_len = suggested_len * 2;
            const min_len = @min(suggested_len, 4);

            comptime var block_len_sum: u16 = max_len;
            inline while (block_len_sum >= min_len) : (block_len_sum /= 2) {
                const block_len = @min(block_len_sum, suggested_len);
                const block_cnt = @max(1, block_len_sum / block_len);
                const Block = @Vector(block_len, T);
                const BoolBlock = @Vector(block_len, bool);

                var blocks: [block_cnt]BoolBlock = undefined;

                if (index + block_len_sum <= shortest) while (true) {
                    const start_index = index;
                    var merged: BoolBlock = undefined;
                    inline for (0..block_cnt) |block_idx| {
                        blocks[block_idx] = @as(Block, a[index..][0..block_len].*) != @as(Block, b[index..][0..block_len].*);
                        if (block_idx == 0) merged = blocks[block_idx] else merged |= blocks[block_idx];
                        index += block_len;
                    }

                    if (@reduce(.Or, merged)) {
                        inline for (0..block_cnt) |block_idx| {
                            if (@reduce(.Or, blocks[block_idx])) {
                                return start_index + block_idx * block_len + std.simd.firstTrue(blocks[block_idx]).?;
                            }
                        }
                        unreachable;
                    }

                    if (block_len_sum == max_len) {
                        if (index + block_len_sum > shortest) break;
                    } else break;
                };
            }

            std.debug.assert(min_len > shortest - index);
        }
    }

    while (index < shortest) : (index += 1) if (a[index] != b[index]) return index;
    return if (a.len == b.len) null else shortest;
}
