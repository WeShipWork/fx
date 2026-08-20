const std = @import("std");

const Allocator = std.mem.Allocator;
pub const max_line_bytes: usize = 32 * 1024 * 1024;

pub const LineReader = struct {
    pending: std.ArrayList(u8) = .empty,

    pub fn deinit(self: *LineReader, alloc: Allocator) void {
        self.pending.deinit(alloc);
        self.* = .{};
    }

    pub fn next(self: *LineReader, alloc: Allocator, reader: anytype) !?[]const u8 {
        self.pending.clearRetainingCapacity();
        while (true) {
            const fragment = reader.takeDelimiter('\n') catch |err| switch (err) {
                error.StreamTooLong => {
                    const buffered = reader.buffered();
                    if (buffered.len == 0) return error.SseReadStalled;
                    if (buffered.len > max_line_bytes - self.pending.items.len) {
                        return error.SseEventTooLarge;
                    }
                    try self.pending.appendSlice(alloc, buffered);
                    reader.tossBuffered();
                    continue;
                },
                error.ReadFailed => return error.ReadFailed,
            } orelse {
                if (self.pending.items.len > 0) return self.pending.items;
                return null;
            };

            if (fragment.len > max_line_bytes - self.pending.items.len) {
                return error.SseEventTooLarge;
            }
            if (self.pending.items.len == 0) return fragment;
            try self.pending.appendSlice(alloc, fragment);
            return self.pending.items;
        }
    }
};

const SplitReader = struct {
    chunks: []const []const u8,
    index: usize = 0,
    last_buffered: []const u8 = "",

    pub fn takeDelimiter(self: *SplitReader, _: u8) error{ StreamTooLong, ReadFailed }!?[]const u8 {
        if (self.index >= self.chunks.len) return null;
        const chunk = self.chunks[self.index];
        self.index += 1;
        if (std.mem.findScalar(u8, chunk, '\n') == null) {
            self.last_buffered = chunk;
            return error.StreamTooLong;
        }
        self.last_buffered = "";
        return if (chunk.len > 0 and chunk[chunk.len - 1] == '\n')
            chunk[0 .. chunk.len - 1]
        else
            chunk;
    }

    pub fn buffered(self: *SplitReader) []const u8 {
        return self.last_buffered;
    }

    pub fn tossBuffered(self: *SplitReader) void {
        self.last_buffered = "";
    }
};

test "SSE line reader reassembles a Codex event that overflows the transfer buffer" {
    const prefix = "data: {\"type\":\"response.output_text.delta\",\"delta\":\"";
    const suffix = "\"}\n";
    const overflow = try std.testing.allocator.alloc(u8, 20 * 1024);
    defer std.testing.allocator.free(overflow);
    @memset(overflow, 'x');

    const first = try std.fmt.allocPrint(std.testing.allocator, "{s}{s}", .{ prefix, overflow[0 .. overflow.len / 2] });
    defer std.testing.allocator.free(first);
    const second = try std.fmt.allocPrint(std.testing.allocator, "{s}{s}", .{ overflow[overflow.len / 2 ..], suffix });
    defer std.testing.allocator.free(second);

    var reader = SplitReader{ .chunks = &.{ first, second } };
    var lines = LineReader{};
    defer lines.deinit(std.testing.allocator);
    const line = (try lines.next(std.testing.allocator, &reader)).?;
    try std.testing.expect(std.mem.startsWith(u8, line, "data: {\"type\":\"response.output_text.delta\""));
    try std.testing.expect(line.len > 16 * 1024);
    try std.testing.expect(try lines.next(std.testing.allocator, &reader) == null);
}

test "SSE line reader without overflow still returns short events" {
    var reader = SplitReader{ .chunks = &.{"data: {\"type\":\"response.created\"}\n"} };
    var lines = LineReader{};
    defer lines.deinit(std.testing.allocator);
    const line = (try lines.next(std.testing.allocator, &reader)).?;
    try std.testing.expectEqualStrings("data: {\"type\":\"response.created\"}", line);
}
