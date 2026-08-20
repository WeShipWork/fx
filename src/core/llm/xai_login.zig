const std = @import("std");
const host = @import("../hosts/host.zig");
const host_target = @import("../hosts/target.zig");
const io_mod = @import("../shared/io.zig");
const oauth = @import("../auth/oauth.zig");
const oauth_transport = @import("../auth/oauth_transport.zig");
const xai = @import("xai.zig");
const xai_oauth = @import("xai_oauth.zig");
const xai_session = @import("xai_session.zig");

const Allocator = std.mem.Allocator;
const poll_wait_slice_ms: u64 = 100;
pub const poll_request_timeout_ms: i64 = 15_000;

pub const LoginError = error{
    LoginTimedOut,
    NoRefreshToken,
};

pub fn runLogin(
    alloc: Allocator,
    transport: oauth_transport.Provider,
    url_opener: host.UrlOpener,
) !void {
    var meta = try xai_oauth.metadata(alloc);
    defer meta.deinit(alloc);

    var device = try xai_oauth.requestDeviceAuthorization(alloc, transport);
    defer device.deinit(alloc);

    const display_url = device.verification_uri_complete orelse device.verification_uri;
    try writeStdout("Open ");
    try writeStdout(display_url);
    try writeStdout("\nCode: ");
    try writeStdout(device.user_code);
    try writeStdout("\n\n");

    var browser_prompt = try BrowserOpenPrompt.init(display_url);
    try browser_prompt.writeWaitingMessage();

    var token = try pollForToken(alloc, transport, meta, device, &browser_prompt, url_opener);
    defer token.deinit(alloc);

    const now_ms = io_mod.milliTimestamp();
    var session = try xai_session.sessionFromTokenSet(alloc, &token, now_ms);
    defer session.deinit(alloc);
    try xai_session.saveNewSession(alloc, session);
    try writeStdout("Signed in to xAI.\n");
    try writeStdout("Use /model xai/grok-4.6 or fx ask --model xai/grok-4.6.\n");
}

pub fn logout() !xai_session.DeleteOutcome {
    return xai_session.deleteSession();
}

fn pollForToken(
    alloc: Allocator,
    transport: oauth_transport.Provider,
    metadata: oauth.Metadata,
    device: oauth.DeviceAuthorization,
    prompt: *BrowserOpenPrompt,
    url_opener: host.UrlOpener,
) !oauth.TokenSet {
    const started_ms = io_mod.milliTimestamp();
    const expires_at_ms = try oauth.expiry_timestamp_ms(started_ms, device.expires_in);
    var interval_ms: u64 = try pollIntervalMs(device.interval);
    var cancel_flag = std.atomic.Value(bool).init(false);

    while (true) {
        const now_ms = io_mod.milliTimestamp();
        if (now_ms >= expires_at_ms) return LoginError.LoginTimedOut;
        try waitBetweenPolls(alloc, prompt, url_opener, interval_ms);

        const deadline = std.Io.Clock.Timestamp.fromNow(io_mod.getIo(), .{
            .clock = .awake,
            .raw = .fromMilliseconds(poll_request_timeout_ms),
        });
        switch (try oauth.pollDeviceTokenBounded(
            alloc,
            transport,
            metadata,
            xai.client_id,
            device.device_code,
            &cancel_flag,
            deadline,
        )) {
            .success => |token| return token,
            .pending => {},
            .slow_down => {
                interval_ms = std.math.add(u64, interval_ms, 5 * std.time.ms_per_s) catch
                    return oauth.OAuthError.InvalidOAuthResponse;
            },
        }
    }
}

fn pollIntervalMs(interval_seconds: i64) oauth.OAuthError!u64 {
    const seconds = @max(interval_seconds, 1);
    const signed_interval_ms = std.math.mul(i64, seconds, std.time.ms_per_s) catch
        return oauth.OAuthError.InvalidOAuthResponse;
    return std.math.cast(u64, signed_interval_ms) orelse oauth.OAuthError.InvalidOAuthResponse;
}

fn waitBetweenPolls(
    alloc: Allocator,
    prompt: *BrowserOpenPrompt,
    url_opener: host.UrlOpener,
    interval_ms: u64,
) !void {
    var remaining_ms = interval_ms;
    while (remaining_ms > 0) {
        const slice_ms = @min(remaining_ms, poll_wait_slice_ms);
        if (prompt.enabled and !prompt.opened) {
            if (waitForEnter(slice_ms)) {
                prompt.opened = true;
                _ = url_opener.open(alloc, prompt.url) catch false;
            }
        } else {
            io_mod.sleep(slice_ms *| @as(u64, 1_000_000));
        }
        remaining_ms -= slice_ms;
    }
}

const BrowserOpenPrompt = struct {
    url: []const u8,
    enabled: bool = false,
    opened: bool = false,

    fn init(url: []const u8) !BrowserOpenPrompt {
        const stdin_is_tty = try std.Io.File.stdin().isTty(io_mod.getIo());
        return .{
            .url = url,
            .enabled = io_mod.getenv("FX_NO_OPEN_BROWSER") == null and
                stdin_is_tty and
                host.current().native_url_open,
        };
    }

    fn writeWaitingMessage(self: BrowserOpenPrompt) !void {
        if (self.enabled) {
            try writeStdout("Waiting for authentication. Press Enter to open this in your browser, or use the URL manually.\n");
        } else {
            try writeStdout("Waiting for authentication...\n");
        }
    }
};

fn waitForEnter(timeout_ms: u64) bool {
    if (comptime host_target.is_wasm) return false;
    var fds = [_]std.posix.pollfd{.{
        .fd = std.posix.STDIN_FILENO,
        .events = std.posix.POLL.IN,
        .revents = 0,
    }};
    const timeout: i32 = @intCast(@min(timeout_ms, @as(u64, @intCast(std.math.maxInt(i32)))));
    const ready = std.posix.poll(&fds, timeout) catch return false;
    if (ready == 0 or (fds[0].revents & std.posix.POLL.IN) == 0) return false;
    var buf: [256]u8 = undefined;
    while (true) {
        const n = std.posix.read(std.posix.STDIN_FILENO, &buf) catch return true;
        if (n == 0) return true;
        if (std.mem.findScalar(u8, buf[0..n], '\n') != null) return true;
    }
}

fn writeStdout(text: []const u8) !void {
    try std.Io.File.stdout().writeStreamingAll(io_mod.getIo(), text);
}
