const std = @import("std");
const agent_stream_provider = @import("../agent/stream_provider.zig");
const io_mod = @import("../shared/io.zig");
const secret = @import("../auth/secret.zig");
const codex = @import("codex.zig");
const codex_oauth = @import("codex_oauth.zig");
const openai_responses = @import("openai_responses.zig");
const sse_lines = @import("sse_lines.zig");

const Allocator = std.mem.Allocator;
const transfer_buffer_bytes: usize = 16 * 1024;

pub fn wrap(comptime inner: agent_stream_provider.Provider) agent_stream_provider.Provider {
    const Holder = struct {
        fn build(_: ?*anyopaque, alloc: Allocator, request: agent_stream_provider.BuildRequest) anyerror![]u8 {
            if (codex.isCodexModel(request.model)) return openai_responses.buildRequestBody(alloc, request);
            return inner.build(alloc, request);
        }

        fn stream(_: ?*anyopaque, alloc: Allocator, request: agent_stream_provider.Request) anyerror!agent_stream_provider.Result {
            if (codex.isCodexModel(request.model)) return streamResponses(alloc, request);
            return inner.stream(alloc, request);
        }
    };
    return .{
        .context = inner.context,
        .build_fn = Holder.build,
        .stream_fn = Holder.stream,
    };
}

fn streamResponses(
    alloc: Allocator,
    request: agent_stream_provider.Request,
) !agent_stream_provider.Result {
    if (request.cancel_flag.load(.seq_cst)) return error.Cancelled;

    const account_id = try codex_oauth.accountIdFromAccessToken(alloc, request.api_key);
    defer alloc.free(account_id);

    var client: std.http.Client = .{ .allocator = alloc, .io = io_mod.getIo() };
    defer client.deinit();

    const uri = std.Uri.parse(codex.responses_url) catch return error.InvalidCodexEndpoint;
    const auth_header = try std.fmt.allocPrint(alloc, "Bearer {s}", .{request.api_key});
    defer secret.zeroAndFree(alloc, auth_header);

    var extra_headers: [7]std.http.Header = undefined;
    extra_headers[0] = .{ .name = "chatgpt-account-id", .value = account_id };
    extra_headers[1] = .{ .name = "originator", .value = codex.originator };
    extra_headers[2] = .{ .name = "OpenAI-Beta", .value = "responses=experimental" };
    extra_headers[3] = .{ .name = "accept", .value = "text/event-stream" };
    var extra_len: usize = 4;
    if (request.session_id) |session_id| {
        extra_headers[extra_len] = .{ .name = "session-id", .value = session_id };
        extra_len += 1;
        extra_headers[extra_len] = .{ .name = "thread-id", .value = session_id };
        extra_len += 1;
        extra_headers[extra_len] = .{ .name = "x-client-request-id", .value = session_id };
        extra_len += 1;
    }

    var req = client.request(.POST, uri, .{
        .headers = .{
            .content_type = .{ .override = "application/json" },
            .authorization = .{ .override = auth_header },
            .accept_encoding = .omit,
            .user_agent = .{ .override = "fx/codex" },
        },
        .extra_headers = extra_headers[0..extra_len],
        .keep_alive = false,
        .redirect_behavior = .unhandled,
    }) catch |err| return err;
    defer req.deinit();

    req.transfer_encoding = .{ .content_length = request.payload.len };
    request.delivery.markPossiblySent();
    var send_buf: [8192]u8 = undefined;
    var body_writer = req.sendBodyUnflushed(&send_buf) catch |err| return err;
    body_writer.writer.writeAll(request.payload) catch |err| return err;
    body_writer.end() catch |err| return err;

    var response = req.receiveHead(&.{}) catch |err| return err;
    if (response.head.status != .ok) {
        var err_out: std.Io.Writer.Allocating = .init(alloc);
        defer err_out.deinit();
        var err_buf: [4096]u8 = undefined;
        const err_reader = response.reader(&err_buf);
        _ = err_reader.streamRemaining(&err_out.writer) catch {};
        return .{
            .status = response.head.status,
            .err_body = err_out.toOwnedSlice() catch null,
            .ownership = .owned,
        };
    }

    var transfer_buf: [transfer_buffer_bytes]u8 = undefined;
    const body_reader = response.reader(&transfer_buf);
    var acc = openai_responses.StreamAccumulator{};
    errdefer acc.deinit(alloc);
    consumeSseReader(
        alloc,
        &acc,
        body_reader,
        request.callback_ctx,
        request.on_content_chunk,
        request.on_tool_start,
        request.on_tool_input_chunk,
        request.on_reasoning_chunk,
        request.cancel_flag,
    ) catch |err| {
        acc.deinit(alloc);
        return err;
    };
    if (request.cancel_flag.load(.seq_cst)) {
        acc.deinit(alloc);
        return error.Cancelled;
    }
    if (acc.failed) {
        acc.deinit(alloc);
        return .{
            .status = .internal_server_error,
            .ownership = .owned,
        };
    }

    const completion = try acc.takeCompletion(alloc);
    return .{
        .status = .ok,
        .completion = completion,
        .ownership = .owned,
    };
}

fn consumeSseReader(
    alloc: Allocator,
    acc: *openai_responses.StreamAccumulator,
    reader: anytype,
    callback_ctx: *anyopaque,
    on_content_chunk: agent_stream_provider.StreamCallback,
    on_tool_start: ?agent_stream_provider.ToolStartCallback,
    on_tool_input_chunk: ?agent_stream_provider.StreamCallback,
    on_reasoning_chunk: ?agent_stream_provider.StreamCallback,
    cancel_flag: *std.atomic.Value(bool),
) !void {
    var lines = sse_lines.LineReader{};
    defer lines.deinit(alloc);
    while (true) {
        if (cancel_flag.load(.seq_cst)) return error.Cancelled;
        const fragment = try lines.next(alloc, reader) orelse break;
        try flushSseLine(
            alloc,
            acc,
            fragment,
            callback_ctx,
            on_content_chunk,
            on_tool_start,
            on_tool_input_chunk,
            on_reasoning_chunk,
        );
    }
}

fn flushSseLine(
    alloc: Allocator,
    acc: *openai_responses.StreamAccumulator,
    line: []const u8,
    callback_ctx: *anyopaque,
    on_content_chunk: agent_stream_provider.StreamCallback,
    on_tool_start: ?agent_stream_provider.ToolStartCallback,
    on_tool_input_chunk: ?agent_stream_provider.StreamCallback,
    on_reasoning_chunk: ?agent_stream_provider.StreamCallback,
) !void {
    const trimmed = std.mem.trim(u8, line, " \t\r");
    if (trimmed.len == 0) return;
    const data = if (std.mem.startsWith(u8, trimmed, "data:"))
        std.mem.trim(u8, trimmed["data:".len..], " \t")
    else if (std.mem.startsWith(u8, trimmed, "event:"))
        return
    else
        trimmed;
    if (data.len == 0) return;
    try openai_responses.consumeSseData(
        alloc,
        acc,
        data,
        callback_ctx,
        on_content_chunk,
        on_tool_start,
        on_tool_input_chunk,
        on_reasoning_chunk,
    );
}

test "Codex dispatch builds responses for openai-codex models and leaves others alone" {
    const Inner = struct {
        fn build(_: ?*anyopaque, alloc: Allocator, request: agent_stream_provider.BuildRequest) anyerror![]u8 {
            return alloc.dupe(u8, request.model);
        }
        fn stream(_: ?*anyopaque, _: Allocator, _: agent_stream_provider.Request) anyerror!agent_stream_provider.Result {
            return error.AgentStreamProviderUnavailable;
        }
    };
    const provider = wrap(.{
        .build_fn = Inner.build,
        .stream_fn = Inner.stream,
    });
    const codex_body = try provider.build(std.testing.allocator, .{
        .model = codex.default_model_ref,
        .serialized_tools = "[]",
        .messages = &.{},
        .tool_choice = .auto,
        .provider_options = .{},
    });
    defer std.testing.allocator.free(codex_body);
    try std.testing.expect(std.mem.find(u8, codex_body, "\"model\":\"gpt-5.4\"") != null);
    try std.testing.expect(std.mem.find(u8, codex_body, "\"store\":false") != null);

    const gateway_body = try provider.build(std.testing.allocator, .{
        .model = "zai/glm-5.2",
        .serialized_tools = "[]",
        .messages = &.{},
        .tool_choice = .auto,
        .provider_options = .{},
    });
    defer std.testing.allocator.free(gateway_body);
    try std.testing.expectEqualStrings("zai/glm-5.2", gateway_body);
}
