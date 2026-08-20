const std = @import("std");
const agent_stream_provider = @import("../agent/stream_provider.zig");
const types = @import("../shared/types.zig");
const codex = @import("codex.zig");

const Allocator = std.mem.Allocator;

pub fn buildRequestBody(alloc: Allocator, request: agent_stream_provider.BuildRequest) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const writer = &out.writer;
    try writer.writeAll("{\"model\":");
    try std.json.Stringify.value(codex.wireModelId(request.model), .{}, writer);
    try writer.writeAll(",\"store\":false,\"stream\":true,\"instructions\":");
    try writeInstructions(writer, request.messages);
    try writer.writeAll(",\"input\":[");
    try writeInputItems(writer, request.messages);
    try writer.writeAll("],\"text\":{\"verbosity\":\"low\"},\"include\":[\"reasoning.encrypted_content\"]");
    try writer.writeAll(",\"tool_choice\":");
    try std.json.Stringify.value(request.tool_choice.label(), .{}, writer);
    try writer.writeAll(",\"parallel_tool_calls\":true");
    if (request.serialized_tools.len > 0 and !std.mem.eql(u8, request.serialized_tools, "[]")) {
        try writer.writeAll(",\"tools\":");
        try writeResponsesTools(alloc, writer, request.serialized_tools);
    }
    if (request.provider_options.reasoning) |*reasoning| {
        if (reasoning.gatewayValue()) |value| {
            try writer.writeAll(",\"reasoning\":{\"effort\":");
            try std.json.Stringify.value(wireReasoningEffort(request.model, value), .{}, writer);
            try writer.writeAll(",\"summary\":\"auto\"}");
        }
    }
    try writer.writeByte('}');
    return out.toOwnedSlice();
}

fn wireReasoningEffort(model: []const u8, effort: []const u8) []const u8 {
    if (std.mem.eql(u8, effort, "minimal")) return "low";
    if (std.mem.eql(u8, effort, "max")) {
        if (codex.modelSpec(model)) |spec| {
            if (!spec.supports_max_effort) return "xhigh";
        }
    }
    return effort;
}

fn writeInstructions(writer: *std.Io.Writer, messages: []const types.ChatMessage) !void {
    var first = true;
    var empty = true;
    try writer.writeByte('"');
    for (messages) |message| {
        if (message.role != .system) continue;
        const content = message.content orelse continue;
        if (content.len == 0) continue;
        if (!first) try writer.writeAll("\\n\\n");
        first = false;
        empty = false;
        try writeJsonStringContents(writer, content);
    }
    if (empty) try writer.writeAll("You are a helpful assistant.");
    try writer.writeByte('"');
}

fn writeInputItems(writer: *std.Io.Writer, messages: []const types.ChatMessage) !void {
    var first = true;
    for (messages) |message| {
        switch (message.role) {
            .system => continue,
            .user => {
                const content = message.content orelse continue;
                if (!first) try writer.writeByte(',');
                first = false;
                try writer.writeAll("{\"role\":\"user\",\"content\":[{\"type\":\"input_text\",\"text\":");
                try std.json.Stringify.value(content, .{}, writer);
                try writer.writeAll("}]}");
            },
            .assistant => {
                if (message.content) |content| {
                    if (content.len > 0) {
                        if (!first) try writer.writeByte(',');
                        first = false;
                        try writer.writeAll("{\"type\":\"message\",\"role\":\"assistant\",\"status\":\"completed\",\"content\":[{\"type\":\"output_text\",\"text\":");
                        try std.json.Stringify.value(content, .{}, writer);
                        try writer.writeAll("}]}");
                    }
                }
                for (message.tool_calls) |call| {
                    if (!first) try writer.writeByte(',');
                    first = false;
                    try writer.writeAll("{\"type\":\"function_call\",\"call_id\":");
                    try std.json.Stringify.value(call.id, .{}, writer);
                    try writer.writeAll(",\"name\":");
                    try std.json.Stringify.value(call.name, .{}, writer);
                    try writer.writeAll(",\"arguments\":");
                    try std.json.Stringify.value(call.arguments_json, .{}, writer);
                    try writer.writeByte('}');
                }
            },
            .tool => {
                if (!first) try writer.writeByte(',');
                first = false;
                try writer.writeAll("{\"type\":\"function_call_output\",\"call_id\":");
                if (message.tool_call_id) |id| {
                    try std.json.Stringify.value(id, .{}, writer);
                } else {
                    try writer.writeAll("\"\"");
                }
                try writer.writeAll(",\"output\":");
                try std.json.Stringify.value(message.content orelse "", .{}, writer);
                try writer.writeByte('}');
            },
        }
    }
}

fn writeResponsesTools(alloc: Allocator, writer: *std.Io.Writer, serialized_tools: []const u8) !void {
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
        if (tool.object.get("function")) |function| {
            if (function == .object) {
                try writeFunctionTool(
                    writer,
                    stringField(function.object, "name"),
                    stringField(function.object, "description"),
                    function.object.get("parameters"),
                );
                continue;
            }
        }
        const name = stringField(tool.object, "name");
        if (name == null) {
            try std.json.Stringify.value(tool, .{}, writer);
            continue;
        }
        try writeFunctionTool(
            writer,
            name,
            stringField(tool.object, "description"),
            tool.object.get("inputSchema") orelse tool.object.get("parameters"),
        );
    }
    try writer.writeByte(']');
}

fn writeFunctionTool(
    writer: *std.Io.Writer,
    name: ?[]const u8,
    description: ?[]const u8,
    parameters: ?std.json.Value,
) !void {
    try writer.writeAll("{\"type\":\"function\",\"name\":");
    try std.json.Stringify.value(name orelse "", .{}, writer);
    try writer.writeAll(",\"description\":");
    try std.json.Stringify.value(description orelse "", .{}, writer);
    try writer.writeAll(",\"strict\":false,\"parameters\":");
    if (parameters) |schema| {
        try std.json.Stringify.value(schema, .{}, writer);
    } else {
        try writer.writeAll("{\"type\":\"object\",\"properties\":{}}");
    }
    try writer.writeByte('}');
}

fn writeJsonStringContents(writer: *std.Io.Writer, value: []const u8) !void {
    for (value) |byte| {
        switch (byte) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (byte < 0x20) {
                    try writer.print("\\u{x:0>4}", .{byte});
                } else {
                    try writer.writeByte(byte);
                }
            },
        }
    }
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
    failed: bool = false,

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
        // Leave a missing finish reason null: the Responses API always emits a
        // terminal response event on a healthy stream, so EOF without one means
        // the stream was truncated. Downstream classification treats a null
        // finish reason as an interrupted response instead of a successful turn.
        if (self.finish_reason == .stop and tool_calls.len > 0) {
            self.finish_reason = .tool_calls;
        }
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
    output_index: usize = 0,
    id: std.ArrayList(u8) = .empty,
    name: std.ArrayList(u8) = .empty,
    arguments: std.ArrayList(u8) = .empty,
    started: bool = false,

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
    on_reasoning_chunk: ?agent_stream_provider.StreamCallback,
) !void {
    if (std.mem.eql(u8, data, "[DONE]")) return;
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, data, .{}) catch return;
    defer parsed.deinit();
    if (parsed.value != .object) return;
    const object = parsed.value.object;
    const event_type = stringField(object, "type") orelse return;

    if (std.mem.eql(u8, event_type, "response.created")) {
        try rememberResponseId(alloc, acc, object.get("response"));
        return;
    }
    if (std.mem.eql(u8, event_type, "response.output_text.delta") or
        std.mem.eql(u8, event_type, "response.refusal.delta"))
    {
        const delta = stringField(object, "delta") orelse return;
        if (delta.len == 0) return;
        try acc.content.appendSlice(alloc, delta);
        if (on_content_chunk) |callback| {
            if (callback_ctx) |ctx| callback(ctx, delta);
        }
        return;
    }
    if (std.mem.eql(u8, event_type, "response.reasoning_summary_text.delta") or
        std.mem.eql(u8, event_type, "response.reasoning_text.delta"))
    {
        const delta = stringField(object, "delta") orelse return;
        if (delta.len == 0) return;
        if (on_reasoning_chunk) |callback| {
            if (callback_ctx) |ctx| callback(ctx, delta);
        }
        return;
    }
    if (std.mem.eql(u8, event_type, "response.output_item.added")) {
        try applyOutputItem(alloc, acc, object, callback_ctx, on_tool_start);
        return;
    }
    if (std.mem.eql(u8, event_type, "response.function_call_arguments.delta")) {
        const delta = stringField(object, "delta") orelse return;
        if (delta.len == 0) return;
        const call = try getOrCreateCall(alloc, acc, integerField(object, "output_index") orelse 0);
        try call.arguments.appendSlice(alloc, delta);
        if (on_tool_input_chunk) |callback| {
            if (callback_ctx) |ctx| callback(ctx, delta);
        }
        return;
    }
    if (std.mem.eql(u8, event_type, "response.function_call_arguments.done")) {
        if (stringField(object, "arguments")) |arguments| {
            const call = try getOrCreateCall(alloc, acc, integerField(object, "output_index") orelse 0);
            if (arguments.len >= call.arguments.items.len) {
                const extra = arguments[call.arguments.items.len..];
                if (extra.len > 0) {
                    try call.arguments.appendSlice(alloc, extra);
                    if (on_tool_input_chunk) |callback| {
                        if (callback_ctx) |ctx| callback(ctx, extra);
                    }
                }
            } else {
                call.arguments.clearRetainingCapacity();
                try call.arguments.appendSlice(alloc, arguments);
            }
        }
        return;
    }
    if (std.mem.eql(u8, event_type, "response.output_item.done")) {
        try applyOutputItem(alloc, acc, object, callback_ctx, on_tool_start);
        return;
    }
    if (std.mem.eql(u8, event_type, "response.completed") or
        std.mem.eql(u8, event_type, "response.incomplete"))
    {
        try finalizeResponse(alloc, acc, object.get("response"));
        return;
    }
    if (std.mem.eql(u8, event_type, "response.failed") or std.mem.eql(u8, event_type, "error")) {
        acc.failed = true;
        acc.finish_reason = .provider_error;
        try rememberResponseId(alloc, acc, object.get("response"));
    }
}

fn applyOutputItem(
    alloc: Allocator,
    acc: *StreamAccumulator,
    object: std.json.ObjectMap,
    callback_ctx: ?*anyopaque,
    on_tool_start: ?agent_stream_provider.ToolStartCallback,
) !void {
    const item_value = object.get("item") orelse return;
    if (item_value != .object) return;
    const item = item_value.object;
    const item_type = stringField(item, "type") orelse return;
    if (!std.mem.eql(u8, item_type, "function_call")) return;

    const call = try getOrCreateCall(alloc, acc, integerField(object, "output_index") orelse 0);
    if (stringField(item, "call_id") orelse stringField(item, "id")) |id| {
        if (call.id.items.len == 0) try call.id.appendSlice(alloc, id);
    }
    const was_unnamed = call.name.items.len == 0;
    if (stringField(item, "name")) |name| {
        if (call.name.items.len == 0) try call.name.appendSlice(alloc, name);
    }
    if (stringField(item, "arguments")) |arguments| {
        if (arguments.len > call.arguments.items.len) {
            try call.arguments.appendSlice(alloc, arguments[call.arguments.items.len..]);
        }
    }
    if (was_unnamed and call.name.items.len > 0 and !call.started) {
        call.started = true;
        if (on_tool_start) |callback| {
            if (callback_ctx) |ctx| callback(ctx, call.id.items, call.name.items, null);
        }
    }
}

fn getOrCreateCall(alloc: Allocator, acc: *StreamAccumulator, output_index: usize) !*PendingToolCall {
    for (acc.tool_calls.items) |*call| {
        if (call.output_index == output_index) return call;
    }
    try acc.tool_calls.append(alloc, .{ .output_index = output_index });
    return &acc.tool_calls.items[acc.tool_calls.items.len - 1];
}

fn rememberResponseId(alloc: Allocator, acc: *StreamAccumulator, response_value: ?std.json.Value) !void {
    const response = response_value orelse return;
    if (response != .object) return;
    const id = stringField(response.object, "id") orelse return;
    if (id.len == 0 or acc.generation_id != null) return;
    acc.generation_id = try alloc.dupe(u8, id);
}

fn finalizeResponse(alloc: Allocator, acc: *StreamAccumulator, response_value: ?std.json.Value) !void {
    const response = response_value orelse return;
    if (response != .object) return;
    try rememberResponseId(alloc, acc, response);
    if (response.object.get("usage")) |usage| {
        if (usage == .object) {
            if (integerField(usage.object, "input_tokens")) |n| acc.usage.input_tokens = n;
            if (integerField(usage.object, "output_tokens")) |n| acc.usage.output_tokens = n;
        }
    }
    const status = stringField(response.object, "status") orelse return;
    if (std.mem.eql(u8, status, "completed")) {
        acc.finish_reason = .stop;
    } else if (std.mem.eql(u8, status, "incomplete")) {
        acc.finish_reason = .length;
    } else if (std.mem.eql(u8, status, "failed") or std.mem.eql(u8, status, "cancelled")) {
        acc.finish_reason = .provider_error;
    }
}

fn takeToolCalls(alloc: Allocator, pending: *std.ArrayList(PendingToolCall)) ![]types.ToolCall {
    var count: usize = 0;
    for (pending.items) |call| {
        if (call.name.items.len > 0) count += 1;
    }
    if (count == 0) return &.{};
    const calls = try alloc.alloc(types.ToolCall, count);
    var copied: usize = 0;
    errdefer {
        for (calls[0..copied]) |call| {
            alloc.free(@constCast(call.id));
            alloc.free(@constCast(call.name));
            alloc.free(@constCast(call.arguments_json));
        }
        alloc.free(calls);
    }
    for (pending.items) |*item| {
        if (item.name.items.len == 0) continue;
        calls[copied] = .{
            .id = try item.id.toOwnedSlice(alloc),
            .name = try item.name.toOwnedSlice(alloc),
            .arguments_json = try item.arguments.toOwnedSlice(alloc),
        };
        copied += 1;
    }
    pending.clearRetainingCapacity();
    return calls;
}

fn integerField(object: std.json.ObjectMap, key: []const u8) ?usize {
    const value = object.get(key) orelse return null;
    return switch (value) {
        .integer => |n| if (n >= 0) @intCast(n) else null,
        else => null,
    };
}

test "responses request uses instructions, input items, and function tools" {
    const messages = [_]types.ChatMessage{
        .{ .role = .system, .content = "be brief" },
        .{ .role = .user, .content = "hi" },
        .{
            .role = .assistant,
            .content = "calling",
            .tool_calls = &.{.{
                .id = "call_1",
                .name = "read_file",
                .arguments_json = "{\"path\":\"a.txt\"}",
            }},
        },
        .{ .role = .tool, .tool_call_id = "call_1", .content = "ok" },
    };
    const body = try buildRequestBody(std.testing.allocator, .{
        .model = codex.default_model_ref,
        .serialized_tools = "[{\"type\":\"function\",\"name\":\"read_file\",\"description\":\"Read\",\"inputSchema\":{\"type\":\"object\",\"properties\":{}}}]",
        .messages = &messages,
        .tool_choice = .auto,
        .provider_options = .{},
        .max_output_tokens = 128,
    });
    defer std.testing.allocator.free(body);

    try std.testing.expect(std.mem.find(u8, body, "\"model\":\"gpt-5.4\"") != null);
    try std.testing.expect(std.mem.find(u8, body, "\"store\":false") != null);
    try std.testing.expect(std.mem.find(u8, body, "\"stream\":true") != null);
    try std.testing.expect(std.mem.find(u8, body, "\"instructions\":\"be brief\"") != null);
    try std.testing.expect(std.mem.find(u8, body, "\"role\":\"user\"") != null);
    try std.testing.expect(std.mem.find(u8, body, "\"type\":\"input_text\"") != null);
    try std.testing.expect(std.mem.find(u8, body, "\"type\":\"function_call\"") != null);
    try std.testing.expect(std.mem.find(u8, body, "\"type\":\"function_call_output\"") != null);
    try std.testing.expect(std.mem.find(u8, body, "\"type\":\"function\",\"name\":\"read_file\"") != null);
    try std.testing.expect(std.mem.find(u8, body, "\"strict\":false") != null);
    try std.testing.expect(std.mem.find(u8, body, "\"tool_choice\":\"auto\"") != null);
    try std.testing.expect(std.mem.find(u8, body, "\"max_output_tokens\"") == null);
    try std.testing.expect(std.mem.find(u8, body, "\"include\":[\"reasoning.encrypted_content\"]") != null);
}

test "responses request maps minimal reasoning to low" {
    const body = try buildRequestBody(std.testing.allocator, .{
        .model = codex.default_model_ref,
        .serialized_tools = "[]",
        .messages = &.{},
        .tool_choice = .auto,
        .provider_options = .{ .reasoning = types.ReasoningEffort.literal("minimal") },
    });
    defer std.testing.allocator.free(body);
    try std.testing.expect(std.mem.find(u8, body, "\"reasoning\":{\"effort\":\"low\",\"summary\":\"auto\"}") != null);
}

test "responses SSE accumulates content and tool calls" {
    var acc = StreamAccumulator{};
    defer acc.deinit(std.testing.allocator);

    try consumeSseData(
        std.testing.allocator,
        &acc,
        "{\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\"}}",
        null,
        null,
        null,
        null,
        null,
    );
    try consumeSseData(
        std.testing.allocator,
        &acc,
        "{\"type\":\"response.output_text.delta\",\"delta\":\"Hel\"}",
        null,
        null,
        null,
        null,
        null,
    );
    try consumeSseData(
        std.testing.allocator,
        &acc,
        "{\"type\":\"response.output_text.delta\",\"delta\":\"lo\"}",
        null,
        null,
        null,
        null,
        null,
    );
    try consumeSseData(
        std.testing.allocator,
        &acc,
        "{\"type\":\"response.output_item.added\",\"output_index\":1,\"item\":{\"type\":\"function_call\",\"call_id\":\"call_1\",\"name\":\"read_file\"}}",
        null,
        null,
        null,
        null,
        null,
    );
    try consumeSseData(
        std.testing.allocator,
        &acc,
        "{\"type\":\"response.function_call_arguments.delta\",\"output_index\":1,\"delta\":\"{\\\"path\\\"\"}",
        null,
        null,
        null,
        null,
        null,
    );
    try consumeSseData(
        std.testing.allocator,
        &acc,
        "{\"type\":\"response.function_call_arguments.done\",\"output_index\":1,\"arguments\":\"{\\\"path\\\":\\\"a.txt\\\"}\"}",
        null,
        null,
        null,
        null,
        null,
    );
    try consumeSseData(
        std.testing.allocator,
        &acc,
        "{\"type\":\"response.completed\",\"response\":{\"id\":\"resp_1\",\"status\":\"completed\",\"usage\":{\"input_tokens\":11,\"output_tokens\":4}}}",
        null,
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
    try std.testing.expectEqualStrings("resp_1", completion.generation_id.?);
}

test "responses SSE accepts an event larger than the HTTP transfer buffer" {
    const sse_lines = @import("sse_lines.zig");
    const delta = try std.testing.allocator.alloc(u8, 20 * 1024);
    defer std.testing.allocator.free(delta);
    @memset(delta, 'a');
    const event = try std.fmt.allocPrint(
        std.testing.allocator,
        "data: {{\"type\":\"response.output_text.delta\",\"delta\":\"{s}\"}}\n",
        .{delta},
    );
    defer std.testing.allocator.free(event);

    const mid = event.len / 2;
    var reader = struct {
        chunks: [2][]const u8,
        index: usize = 0,
        last_buffered: []const u8 = "",

        pub fn takeDelimiter(self: *@This(), _: u8) error{ StreamTooLong, ReadFailed }!?[]const u8 {
            if (self.index >= self.chunks.len) return null;
            const chunk = self.chunks[self.index];
            self.index += 1;
            if (std.mem.findScalar(u8, chunk, '\n') == null) {
                self.last_buffered = chunk;
                return error.StreamTooLong;
            }
            self.last_buffered = "";
            return chunk[0 .. chunk.len - 1];
        }
        pub fn buffered(self: *@This()) []const u8 {
            return self.last_buffered;
        }
        pub fn tossBuffered(self: *@This()) void {
            self.last_buffered = "";
        }
    }{ .chunks = .{ event[0..mid], event[mid..] } };

    var acc = StreamAccumulator{};
    defer acc.deinit(std.testing.allocator);
    var lines = sse_lines.LineReader{};
    defer lines.deinit(std.testing.allocator);
    while (try lines.next(std.testing.allocator, &reader)) |line| {
        const data = std.mem.trim(u8, line["data:".len..], " \t");
        try consumeSseData(std.testing.allocator, &acc, data, null, null, null, null, null);
    }
    const completion = try acc.takeCompletion(std.testing.allocator);
    defer if (completion.content) |content| std.testing.allocator.free(@constCast(content));
    try std.testing.expectEqual(@as(usize, 20 * 1024), completion.content.?.len);
}

test "responses SSE without a terminal event keeps finish reason null" {
    var acc = StreamAccumulator{};
    defer acc.deinit(std.testing.allocator);

    try consumeSseData(
        std.testing.allocator,
        &acc,
        "{\"type\":\"response.created\",\"response\":{\"id\":\"resp_1\"}}",
        null,
        null,
        null,
        null,
        null,
    );
    try consumeSseData(
        std.testing.allocator,
        &acc,
        "{\"type\":\"response.output_text.delta\",\"delta\":\"partial\"}",
        null,
        null,
        null,
        null,
        null,
    );

    const completion = try acc.takeCompletion(std.testing.allocator);
    defer {
        if (completion.content) |content| std.testing.allocator.free(@constCast(content));
        if (completion.generation_id) |id| std.testing.allocator.free(@constCast(id));
    }
    try std.testing.expectEqualStrings("partial", completion.content.?);
    try std.testing.expect(completion.finish_reason == null);
    try std.testing.expectEqual(
        types.ProviderCompletionDisposition.interrupted,
        types.classifyProviderCompletion(completion),
    );
}
