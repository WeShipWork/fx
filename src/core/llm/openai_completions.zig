const std = @import("std");
const agent_stream_provider = @import("../agent/stream_provider.zig");
const types = @import("../shared/types.zig");
const xai = @import("xai.zig");

const Allocator = std.mem.Allocator;

pub fn buildRequestBody(alloc: Allocator, request: agent_stream_provider.BuildRequest) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const writer = &out.writer;
    try writer.writeAll("{\"model\":");
    try std.json.Stringify.value(xai.wireModelId(request.model), .{}, writer);
    try writer.writeAll(",\"stream\":true,\"stream_options\":{\"include_usage\":true},\"messages\":[");
    for (request.messages, 0..) |message, index| {
        if (index > 0) try writer.writeByte(',');
        try writeMessage(writer, message);
    }
    try writer.writeByte(']');
    if (request.serialized_tools.len > 0 and !std.mem.eql(u8, request.serialized_tools, "[]")) {
        try writer.writeAll(",\"tools\":");
        try writeOpenAiTools(alloc, writer, request.serialized_tools);
    }
    try writer.writeAll(",\"tool_choice\":");
    try std.json.Stringify.value(request.tool_choice.label(), .{}, writer);
    if (request.provider_options.reasoning) |*reasoning| {
        if (reasoning.gatewayValue()) |value| {
            try writer.writeAll(",\"reasoning_effort\":");
            try std.json.Stringify.value(value, .{}, writer);
        }
    }
    if (request.max_output_tokens) |max_tokens| {
        try writer.print(",\"max_tokens\":{d}", .{max_tokens});
    }
    try writer.writeByte('}');
    return out.toOwnedSlice();
}

fn writeMessage(writer: *std.Io.Writer, message: types.ChatMessage) !void {
    try writer.writeAll("{\"role\":");
    try std.json.Stringify.value(roleName(message.role), .{}, writer);
    if (message.role == .tool) {
        if (message.tool_call_id) |id| {
            try writer.writeAll(",\"tool_call_id\":");
            try std.json.Stringify.value(id, .{}, writer);
        }
        if (message.tool_name) |name| {
            try writer.writeAll(",\"name\":");
            try std.json.Stringify.value(name, .{}, writer);
        }
    }
    if (message.tool_calls.len > 0) {
        try writer.writeAll(",\"tool_calls\":[");
        for (message.tool_calls, 0..) |call, index| {
            if (index > 0) try writer.writeByte(',');
            try writer.writeAll("{\"id\":");
            try std.json.Stringify.value(call.id, .{}, writer);
            try writer.writeAll(",\"type\":\"function\",\"function\":{\"name\":");
            try std.json.Stringify.value(call.name, .{}, writer);
            try writer.writeAll(",\"arguments\":");
            try std.json.Stringify.value(call.arguments_json, .{}, writer);
            try writer.writeAll("}}");
        }
        try writer.writeByte(']');
    }
    try writer.writeAll(",\"content\":");
    if (message.content) |content| {
        try std.json.Stringify.value(content, .{}, writer);
    } else {
        try writer.writeAll("null");
    }
    try writer.writeByte('}');
}

fn roleName(role: types.ChatRole) []const u8 {
    return switch (role) {
        .system => "system",
        .user => "user",
        .assistant => "assistant",
        .tool => "tool",
    };
}

fn writeOpenAiTools(alloc: Allocator, writer: *std.Io.Writer, serialized_tools: []const u8) !void {
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, serialized_tools, .{});
    defer parsed.deinit();
    if (parsed.value != .array) {
        try writer.writeAll(serialized_tools);
        return;
    }
    try writer.writeByte('[');
    for (parsed.value.array.items, 0..) |tool, index| {
        if (index > 0) try writer.writeByte(',');
        if (tool != .object) {
            try std.json.Stringify.value(tool, .{}, writer);
            continue;
        }
        if (tool.object.get("function") != null) {
            try std.json.Stringify.value(tool, .{}, writer);
            continue;
        }
        const name = stringField(tool.object, "name") orelse {
            try std.json.Stringify.value(tool, .{}, writer);
            continue;
        };
        const description = stringField(tool.object, "description") orelse "";
        const parameters = tool.object.get("inputSchema") orelse tool.object.get("parameters");
        try writer.writeAll("{\"type\":\"function\",\"function\":{\"name\":");
        try std.json.Stringify.value(name, .{}, writer);
        try writer.writeAll(",\"description\":");
        try std.json.Stringify.value(description, .{}, writer);
        try writer.writeAll(",\"parameters\":");
        if (parameters) |schema| {
            try std.json.Stringify.value(schema, .{}, writer);
        } else {
            try writer.writeAll("{\"type\":\"object\",\"properties\":{}}");
        }
        try writer.writeAll("}}");
    }
    try writer.writeByte(']');
}

fn stringField(object: std.json.ObjectMap, key: []const u8) ?[]const u8 {
    const value = object.get(key) orelse return null;
    return if (value == .string) value.string else null;
}

pub const StreamAccumulator = struct {
    content: std.ArrayList(u8) = .empty,
    tool_calls: std.ArrayList(PendingToolCall) = .empty,
    finish_reason: ?types.ProviderFinishReason = null,
    usage: types.Usage = .{},
    generation_id: ?[]u8 = null,

    pub fn deinit(self: *StreamAccumulator, alloc: Allocator) void {
        self.content.deinit(alloc);
        for (self.tool_calls.items) |*call| call.deinit(alloc);
        self.tool_calls.deinit(alloc);
        if (self.generation_id) |id| alloc.free(id);
        self.* = .{};
    }

    pub fn takeCompletion(self: *StreamAccumulator, alloc: Allocator) !types.GatewayCompletion {
        const content = if (self.content.items.len == 0)
            null
        else
            try self.content.toOwnedSlice(alloc);
        errdefer if (content) |value| alloc.free(value);
        const tool_calls = try takeToolCalls(alloc, &self.tool_calls);
        errdefer types.freeToolCallSlice(alloc, tool_calls);
        const generation_id = self.generation_id;
        self.generation_id = null;
        return .{
            .content = content,
            .tool_calls = tool_calls,
            .generation_id = generation_id,
            .finish_reason = self.finish_reason,
            .usage = self.usage,
        };
    }
};

const PendingToolCall = struct {
    id: std.ArrayList(u8) = .empty,
    name: std.ArrayList(u8) = .empty,
    arguments: std.ArrayList(u8) = .empty,

    fn deinit(self: *PendingToolCall, alloc: Allocator) void {
        self.id.deinit(alloc);
        self.name.deinit(alloc);
        self.arguments.deinit(alloc);
        self.* = .{};
    }
};

pub fn consumeSseData(
    alloc: Allocator,
    acc: *StreamAccumulator,
    data: []const u8,
    callback_ctx: ?*anyopaque,
    on_content_chunk: ?agent_stream_provider.StreamCallback,
    on_tool_start: ?agent_stream_provider.ToolStartCallback,
    on_tool_input_chunk: ?agent_stream_provider.StreamCallback,
) !void {
    if (std.mem.eql(u8, data, "[DONE]")) return;
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, data, .{}) catch return;
    defer parsed.deinit();
    if (parsed.value != .object) return;
    const object = parsed.value.object;

    if (object.get("id")) |id| {
        if (id == .string and id.string.len > 0 and acc.generation_id == null) {
            acc.generation_id = try alloc.dupe(u8, id.string);
        }
    }
    if (object.get("usage")) |usage| {
        if (usage == .object) {
            if (integerField(usage.object, "prompt_tokens")) |n| acc.usage.input_tokens = n;
            if (integerField(usage.object, "completion_tokens")) |n| acc.usage.output_tokens = n;
        }
    }
    const choices = object.get("choices") orelse return;
    if (choices != .array or choices.array.items.len == 0) return;
    const choice = choices.array.items[0];
    if (choice != .object) return;

    if (choice.object.get("finish_reason")) |reason| {
        if (reason == .string) {
            acc.finish_reason = types.ProviderFinishReason.parse_legacy(reason.string) orelse
                types.ProviderFinishReason.parse_unified(reason.string) orelse
                .other;
        }
    }
    const delta = choice.object.get("delta") orelse return;
    if (delta != .object) return;

    if (delta.object.get("content")) |content| {
        if (content == .string and content.string.len > 0) {
            try acc.content.appendSlice(alloc, content.string);
            if (on_content_chunk) |callback| {
                if (callback_ctx) |ctx| callback(ctx, content.string);
            }
        }
    }
    if (delta.object.get("tool_calls")) |tool_calls| {
        if (tool_calls == .array) {
            for (tool_calls.array.items) |item| {
                if (item != .object) continue;
                try applyToolCallDelta(alloc, acc, item.object, callback_ctx, on_tool_start, on_tool_input_chunk);
            }
        }
    }
}

fn applyToolCallDelta(
    alloc: Allocator,
    acc: *StreamAccumulator,
    object: std.json.ObjectMap,
    callback_ctx: ?*anyopaque,
    on_tool_start: ?agent_stream_provider.ToolStartCallback,
    on_tool_input_chunk: ?agent_stream_provider.StreamCallback,
) !void {
    const index = integerField(object, "index") orelse 0;
    while (acc.tool_calls.items.len <= index) {
        try acc.tool_calls.append(alloc, .{});
    }
    const call = &acc.tool_calls.items[index];
    const was_unnamed = call.name.items.len == 0;
    if (object.get("id")) |id| {
        if (id == .string) try call.id.appendSlice(alloc, id.string);
    }
    if (object.get("function")) |function| {
        if (function == .object) {
            if (function.object.get("name")) |name| {
                if (name == .string) try call.name.appendSlice(alloc, name.string);
            }
            if (function.object.get("arguments")) |arguments| {
                if (arguments == .string and arguments.string.len > 0) {
                    try call.arguments.appendSlice(alloc, arguments.string);
                    if (on_tool_input_chunk) |callback| {
                        if (callback_ctx) |ctx| callback(ctx, arguments.string);
                    }
                }
            }
        }
    }
    if (was_unnamed and call.name.items.len > 0) {
        if (on_tool_start) |callback| {
            if (callback_ctx) |ctx| callback(ctx, call.id.items, call.name.items, null);
        }
    }
}

fn takeToolCalls(alloc: Allocator, pending: *std.ArrayList(PendingToolCall)) ![]types.ToolCall {
    if (pending.items.len == 0) return &.{};
    const calls = try alloc.alloc(types.ToolCall, pending.items.len);
    var copied: usize = 0;
    errdefer {
        for (calls[0..copied]) |call| {
            alloc.free(@constCast(call.id));
            alloc.free(@constCast(call.name));
            alloc.free(@constCast(call.arguments_json));
        }
        alloc.free(calls);
    }
    for (pending.items, 0..) |*item, i| {
        calls[i] = .{
            .id = try item.id.toOwnedSlice(alloc),
            .name = try item.name.toOwnedSlice(alloc),
            .arguments_json = try item.arguments.toOwnedSlice(alloc),
        };
        copied += 1;
    }
    pending.clearRetainingCapacity();
    return calls;
}

fn integerField(object: std.json.ObjectMap, key: []const u8) ?u64 {
    const value = object.get(key) orelse return null;
    return switch (value) {
        .integer => |n| if (n >= 0) @intCast(n) else null,
        else => null,
    };
}

test "completions request uses the wire model and converts gateway tools" {
    const messages = [_]types.ChatMessage{
        .{ .role = .system, .content = "be brief" },
        .{ .role = .user, .content = "hi" },
    };
    const body = try buildRequestBody(std.testing.allocator, .{
        .model = xai.model_ref,
        .serialized_tools = "[{\"type\":\"function\",\"name\":\"read_file\",\"description\":\"Read\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}}]",
        .messages = &messages,
        .tool_choice = .auto,
        .provider_options = .{},
        .max_output_tokens = 128,
    });
    defer std.testing.allocator.free(body);

    try std.testing.expect(std.mem.find(u8, body, "\"model\":\"grok-4.6\"") != null);
    try std.testing.expect(std.mem.find(u8, body, "\"stream\":true") != null);
    try std.testing.expect(std.mem.find(u8, body, "\"role\":\"system\"") != null);
    try std.testing.expect(std.mem.find(u8, body, "\"role\":\"user\"") != null);
    try std.testing.expect(std.mem.find(u8, body, "\"function\":{\"name\":\"read_file\"") != null);
    try std.testing.expect(std.mem.find(u8, body, "\"parameters\":{\"type\":\"object\"") != null);
    try std.testing.expect(std.mem.find(u8, body, "\"tool_choice\":\"auto\"") != null);
    try std.testing.expect(std.mem.find(u8, body, "\"max_tokens\":128") != null);
    try std.testing.expect(std.mem.find(u8, body, "reasoning_effort") == null);
    try std.testing.expect(std.mem.find(u8, body, "\"store\"") == null);
}

test "completions request sends named xAI reasoning effort" {
    const body = try buildRequestBody(std.testing.allocator, .{
        .model = xai.model_ref,
        .serialized_tools = "[]",
        .messages = &.{},
        .tool_choice = .auto,
        .provider_options = .{ .reasoning = types.ReasoningEffort.literal("high") },
    });
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.find(u8, body, "\"reasoning_effort\":\"high\"") != null);
}

test "completions SSE accumulates content and tool calls" {
    var acc = StreamAccumulator{};
    defer acc.deinit(std.testing.allocator);

    try consumeSseData(std.testing.allocator, &acc, "{\"id\":\"chatcmpl_1\",\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}", null, null, null, null);
    try consumeSseData(std.testing.allocator, &acc, "{\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}", null, null, null, null);
    try consumeSseData(
        std.testing.allocator,
        &acc,
        "{\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"read_file\",\"arguments\":\"{\\\"path\\\"\"}}]}}]}",
        null,
        null,
        null,
        null,
    );
    try consumeSseData(
        std.testing.allocator,
        &acc,
        "{\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\":\\\"a.txt\\\"}\"}}]},\"finish_reason\":\"tool_calls\"}]}",
        null,
        null,
        null,
        null,
    );
    try consumeSseData(
        std.testing.allocator,
        &acc,
        "{\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":4},\"choices\":[]}",
        null,
        null,
        null,
        null,
    );

    const completion = try acc.takeCompletion(std.testing.allocator);
    defer {
        if (completion.content) |content| std.testing.allocator.free(@constCast(content));
        if (completion.generation_id) |id| std.testing.allocator.free(@constCast(id));
        types.freeToolCallSlice(std.testing.allocator, @constCast(completion.tool_calls));
    }
    try std.testing.expectEqualStrings("Hello", completion.content.?);
    try std.testing.expectEqual(@as(usize, 1), completion.tool_calls.len);
    try std.testing.expectEqualStrings("call_1", completion.tool_calls[0].id);
    try std.testing.expectEqualStrings("read_file", completion.tool_calls[0].name);
    try std.testing.expectEqualStrings("{\"path\":\"a.txt\"}", completion.tool_calls[0].arguments_json);
    try std.testing.expectEqual(types.ProviderFinishReason.tool_calls, completion.finish_reason.?);
    try std.testing.expectEqual(@as(u64, 11), completion.usage.input_tokens.?);
    try std.testing.expectEqual(@as(u64, 4), completion.usage.output_tokens.?);
}
