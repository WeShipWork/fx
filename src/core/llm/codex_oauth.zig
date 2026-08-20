const std = @import("std");
const oauth = @import("../auth/oauth.zig");
const oauth_transport = @import("../auth/oauth_transport.zig");
const secret = @import("../auth/secret.zig");
const codex = @import("codex.zig");

const Allocator = std.mem.Allocator;

pub const DeviceAuth = struct {
    device_auth_id: []u8,
    user_code: []u8,
    interval_seconds: i64,

    pub fn deinit(self: *DeviceAuth, alloc: Allocator) void {
        alloc.free(self.device_auth_id);
        alloc.free(self.user_code);
        self.* = undefined;
    }
};

pub const DeviceAuthCode = struct {
    authorization_code: []u8,
    code_verifier: []u8,

    pub fn deinit(self: *DeviceAuthCode, alloc: Allocator) void {
        secret.zeroAndFree(alloc, self.authorization_code);
        secret.zeroAndFree(alloc, self.code_verifier);
        self.* = undefined;
    }
};

pub const PollOutcome = union(enum) {
    success: DeviceAuthCode,
    pending,
    slow_down,
};

pub fn requestDeviceAuthorization(
    alloc: Allocator,
    transport: oauth_transport.Provider,
) !DeviceAuth {
    const payload = try std.fmt.allocPrint(alloc, "{{\"client_id\":{f}}}", .{std.json.fmt(codex.client_id, .{})});
    defer alloc.free(payload);

    var response = try transport.execute(alloc, .{
        .method = .post_json,
        .url = codex.device_user_code_url,
        .payload = payload,
    });
    defer response.deinit(alloc);
    if (response.disposition != .accepted) {
        if (response.status == 404) return oauth.OAuthError.InvalidClient;
        try mapRejected(alloc, response.body);
        return oauth.OAuthError.OAuthRequestFailed;
    }

    const body = response.takeBody();
    defer secret.zeroAndFree(alloc, body);
    return parseDeviceAuth(alloc, body);
}

pub fn pollDeviceAuthorization(
    alloc: Allocator,
    transport: oauth_transport.Provider,
    device: DeviceAuth,
) !PollOutcome {
    const payload = try std.fmt.allocPrint(
        alloc,
        "{{\"device_auth_id\":{f},\"user_code\":{f}}}",
        .{ std.json.fmt(device.device_auth_id, .{}), std.json.fmt(device.user_code, .{}) },
    );
    defer alloc.free(payload);

    var response = try transport.execute(alloc, .{
        .method = .post_json,
        .url = codex.device_token_url,
        .payload = payload,
    });
    defer response.deinit(alloc);
    if (response.disposition == .accepted) {
        const body = response.takeBody();
        defer secret.zeroAndFree(alloc, body);
        return .{ .success = try parseDeviceAuthCode(alloc, body) };
    }
    if (response.status == 403 or response.status == 404) return .pending;
    return switch (try rejectedPollStatus(alloc, response.body)) {
        .pending => .pending,
        .slow_down => .slow_down,
        .failed => oauth.OAuthError.OAuthRequestFailed,
    };
}

pub fn exchangeAuthorizationCode(
    alloc: Allocator,
    transport: oauth_transport.Provider,
    code: []const u8,
    verifier: []const u8,
    redirect_uri: []const u8,
) !oauth.TokenSet {
    var form: FormBody = .{};
    var writer: std.Io.Writer.Allocating = .init(alloc);
    defer writer.deinit();
    try form.append(&writer.writer, "grant_type", "authorization_code");
    try form.append(&writer.writer, "client_id", codex.client_id);
    try form.append(&writer.writer, "code", code);
    try form.append(&writer.writer, "code_verifier", verifier);
    try form.append(&writer.writer, "redirect_uri", redirect_uri);

    var response = try transport.execute(alloc, .{
        .method = .post_form,
        .url = codex.token_url,
        .payload = writer.written(),
    });
    defer response.deinit(alloc);
    if (response.disposition != .accepted) {
        try mapRejected(alloc, response.body);
        return oauth.OAuthError.OAuthRequestFailed;
    }
    const body = response.takeBody();
    defer secret.zeroAndFree(alloc, body);
    return parseTokenSet(alloc, body, null);
}

pub fn refreshToken(
    alloc: Allocator,
    transport: oauth_transport.Provider,
    refresh_token: []const u8,
) !oauth.TokenSet {
    var form: FormBody = .{};
    var writer: std.Io.Writer.Allocating = .init(alloc);
    defer writer.deinit();
    try form.append(&writer.writer, "grant_type", "refresh_token");
    try form.append(&writer.writer, "refresh_token", refresh_token);
    try form.append(&writer.writer, "client_id", codex.client_id);

    var response = try transport.execute(alloc, .{
        .method = .post_form,
        .url = codex.token_url,
        .payload = writer.written(),
    });
    defer response.deinit(alloc);
    if (response.disposition != .accepted) {
        try mapRejected(alloc, response.body);
        return oauth.OAuthError.OAuthRequestFailed;
    }
    const body = response.takeBody();
    defer secret.zeroAndFree(alloc, body);
    return parseTokenSet(alloc, body, refresh_token);
}

pub fn parseTokenSet(alloc: Allocator, bytes: []const u8, previous_refresh: ?[]const u8) !oauth.TokenSet {
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, bytes, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return oauth.OAuthError.InvalidOAuthResponse;
    const object = parsed.value.object;

    const access_token = try dupeRequiredString(alloc, object, "access_token");
    errdefer secret.zeroAndFree(alloc, access_token);

    const refresh_token = blk: {
        if (object.get("refresh_token")) |value| {
            if (value == .string and value.string.len > 0) {
                break :blk try alloc.dupe(u8, value.string);
            }
        }
        if (previous_refresh) |value| {
            if (value.len > 0) break :blk try alloc.dupe(u8, value);
        }
        return oauth.OAuthError.InvalidOAuthResponse;
    };
    errdefer secret.zeroAndFree(alloc, refresh_token);

    const token_type = if (object.get("token_type")) |value|
        if (value == .string and value.string.len > 0)
            try alloc.dupe(u8, value.string)
        else
            try alloc.dupe(u8, "Bearer")
    else
        try alloc.dupe(u8, "Bearer");
    errdefer alloc.free(token_type);
    if (!std.ascii.eqlIgnoreCase(token_type, "Bearer")) return oauth.OAuthError.InvalidOAuthResponse;

    const scope = if (object.get("scope")) |value|
        if (value == .string) try alloc.dupe(u8, value.string) else try alloc.dupe(u8, "")
    else
        try alloc.dupe(u8, "");
    errdefer alloc.free(scope);

    const expires_in = if (object.get("expires_in")) |value|
        switch (value) {
            .integer => |n| n,
            .float => |n| @as(i64, @intFromFloat(n)),
            else => return oauth.OAuthError.InvalidOAuthResponse,
        }
    else
        return oauth.OAuthError.InvalidOAuthResponse;
    if (expires_in <= 0) return oauth.OAuthError.InvalidOAuthResponse;

    return .{
        .access_token = access_token,
        .refresh_token = refresh_token,
        .expires_in = expires_in,
        .scope = scope,
        .token_type = token_type,
    };
}

pub fn accountIdFromAccessToken(alloc: Allocator, access_token: []const u8) ![]u8 {
    const payload = try decodeJwtPayload(alloc, access_token);
    defer alloc.free(payload);

    var parsed = std.json.parseFromSlice(std.json.Value, alloc, payload, .{}) catch
        return oauth.OAuthError.InvalidOAuthResponse;
    defer parsed.deinit();
    if (parsed.value != .object) return oauth.OAuthError.InvalidOAuthResponse;
    const auth = parsed.value.object.get(codex.jwt_auth_claim) orelse
        return oauth.OAuthError.InvalidOAuthResponse;
    if (auth != .object) return oauth.OAuthError.InvalidOAuthResponse;
    const account_id = auth.object.get("chatgpt_account_id") orelse
        return oauth.OAuthError.InvalidOAuthResponse;
    if (account_id != .string or account_id.string.len == 0)
        return oauth.OAuthError.InvalidOAuthResponse;
    return alloc.dupe(u8, account_id.string);
}

fn parseDeviceAuth(alloc: Allocator, bytes: []const u8) !DeviceAuth {
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, bytes, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return oauth.OAuthError.InvalidOAuthResponse;
    const object = parsed.value.object;
    const device_auth_id = try dupeRequiredString(alloc, object, "device_auth_id");
    errdefer alloc.free(device_auth_id);
    const user_code = try dupeRequiredString(alloc, object, "user_code");
    errdefer alloc.free(user_code);
    const interval_seconds = parseInterval(object.get("interval")) orelse
        return oauth.OAuthError.InvalidOAuthResponse;
    return .{
        .device_auth_id = device_auth_id,
        .user_code = user_code,
        .interval_seconds = interval_seconds,
    };
}

fn parseDeviceAuthCode(alloc: Allocator, bytes: []const u8) !DeviceAuthCode {
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, bytes, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return oauth.OAuthError.InvalidOAuthResponse;
    const object = parsed.value.object;
    const authorization_code = try dupeRequiredString(alloc, object, "authorization_code");
    errdefer secret.zeroAndFree(alloc, authorization_code);
    const code_verifier = try dupeRequiredString(alloc, object, "code_verifier");
    errdefer secret.zeroAndFree(alloc, code_verifier);
    return .{
        .authorization_code = authorization_code,
        .code_verifier = code_verifier,
    };
}

fn parseInterval(value: ?std.json.Value) ?i64 {
    const raw = value orelse return null;
    return switch (raw) {
        .integer => |n| if (n >= 0) n else null,
        .float => |n| if (n >= 0) @as(i64, @intFromFloat(n)) else null,
        .string => |text| {
            const trimmed = std.mem.trim(u8, text, " \t\r\n");
            const parsed = std.fmt.parseInt(i64, trimmed, 10) catch return null;
            return if (parsed >= 0) parsed else null;
        },
        else => null,
    };
}

const PollStatus = enum { pending, slow_down, failed };

fn rejectedPollStatus(alloc: Allocator, body: []const u8) !PollStatus {
    mapRejected(alloc, body) catch |err| switch (err) {
        oauth.OAuthError.AuthorizationPending => return .pending,
        oauth.OAuthError.SlowDown => return .slow_down,
        else => return .failed,
    };
    return .failed;
}

fn mapRejected(alloc: Allocator, body: []const u8) !void {
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, body, .{}) catch
        return oauth.OAuthError.OAuthRequestFailed;
    defer parsed.deinit();
    if (parsed.value != .object) return oauth.OAuthError.OAuthRequestFailed;
    const code = errorCode(parsed.value.object) orelse return oauth.OAuthError.OAuthRequestFailed;
    if (std.mem.eql(u8, code, "authorization_pending") or
        std.mem.eql(u8, code, "deviceauth_authorization_pending"))
        return oauth.OAuthError.AuthorizationPending;
    if (std.mem.eql(u8, code, "slow_down")) return oauth.OAuthError.SlowDown;
    if (std.mem.eql(u8, code, "access_denied") or
        std.mem.eql(u8, code, "authorization_denied"))
        return oauth.OAuthError.AccessDenied;
    if (std.mem.eql(u8, code, "expired_token")) return oauth.OAuthError.ExpiredToken;
    if (std.mem.eql(u8, code, "invalid_client")) return oauth.OAuthError.InvalidClient;
    return oauth.OAuthError.OAuthRequestFailed;
}

fn errorCode(object: std.json.ObjectMap) ?[]const u8 {
    const value = object.get("error") orelse return null;
    return switch (value) {
        .string => |text| text,
        .object => |nested| blk: {
            const code = nested.get("code") orelse return null;
            break :blk if (code == .string) code.string else null;
        },
        else => null,
    };
}

fn decodeJwtPayload(alloc: Allocator, token: []const u8) ![]u8 {
    var parts = std.mem.splitScalar(u8, token, '.');
    _ = parts.next() orelse return oauth.OAuthError.InvalidOAuthResponse;
    const payload = parts.next() orelse return oauth.OAuthError.InvalidOAuthResponse;
    if (payload.len == 0 or parts.next() == null) return oauth.OAuthError.InvalidOAuthResponse;

    const decoded_len = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(payload) catch
        return oauth.OAuthError.InvalidOAuthResponse;
    const decoded = try alloc.alloc(u8, decoded_len);
    errdefer alloc.free(decoded);
    std.base64.url_safe_no_pad.Decoder.decode(decoded, payload) catch
        return oauth.OAuthError.InvalidOAuthResponse;
    return decoded;
}

const FormBody = struct {
    first: bool = true,

    fn append(self: *FormBody, writer: *std.Io.Writer, key: []const u8, value: []const u8) !void {
        if (!self.first) try writer.writeAll("&");
        self.first = false;
        try percentEncode(writer, key);
        try writer.writeAll("=");
        try percentEncode(writer, value);
    }
};

fn percentEncode(writer: *std.Io.Writer, value: []const u8) !void {
    const hex = "0123456789ABCDEF";
    for (value) |byte| {
        const safe = std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '_' or byte == '.' or byte == '~';
        if (safe) {
            try writer.writeByte(byte);
        } else {
            try writer.writeByte('%');
            try writer.writeByte(hex[byte >> 4]);
            try writer.writeByte(hex[byte & 0x0f]);
        }
    }
}

fn dupeRequiredString(alloc: Allocator, object: std.json.ObjectMap, key: []const u8) ![]u8 {
    const value = object.get(key) orelse return oauth.OAuthError.InvalidOAuthResponse;
    if (value != .string or value.string.len == 0) return oauth.OAuthError.InvalidOAuthResponse;
    return alloc.dupe(u8, value.string);
}

const TransportProbe = struct {
    expected_method: oauth_transport.Method,
    expected_url: []const u8,
    expected_payload: []const u8,
    response_disposition: oauth_transport.Disposition = .accepted,
    response_status: u16 = 200,
    response_body: []const u8,
    matched: bool = false,

    fn provider(self: *TransportProbe) oauth_transport.Provider {
        return .{
            .context = self,
            .execute_fn = execute,
        };
    }

    fn execute(raw: ?*anyopaque, alloc: Allocator, request: oauth_transport.Request) !oauth_transport.Response {
        const self: *TransportProbe = @ptrCast(@alignCast(raw.?));
        self.matched = request.method == self.expected_method and
            std.mem.eql(u8, request.url, self.expected_url) and
            request.payload != null and
            std.mem.eql(u8, request.payload.?, self.expected_payload);
        return .{
            .disposition = self.response_disposition,
            .status = self.response_status,
            .body = try alloc.dupe(u8, self.response_body),
        };
    }
};

fn encodeJwt(alloc: Allocator, payload: []const u8) ![]u8 {
    const encoded_len = std.base64.url_safe_no_pad.Encoder.calcSize(payload.len);
    const encoded = try alloc.alloc(u8, encoded_len);
    _ = std.base64.url_safe_no_pad.Encoder.encode(encoded, payload);
    return encoded;
}

test "Codex device authorization posts JSON client_id" {
    var probe = TransportProbe{
        .expected_method = .post_json,
        .expected_url = codex.device_user_code_url,
        .expected_payload = "{\"client_id\":\"app_EMoamEEZ73f0CkXaXp7hrann\"}",
        .response_body = "{\"device_auth_id\":\"dev-1\",\"user_code\":\"ABCD-1234\",\"interval\":5}",
    };
    var device = try requestDeviceAuthorization(std.testing.allocator, probe.provider());
    defer device.deinit(std.testing.allocator);
    try std.testing.expect(probe.matched);
    try std.testing.expectEqualStrings("ABCD-1234", device.user_code);
    try std.testing.expectEqual(@as(i64, 5), device.interval_seconds);
}

test "Codex device poll treats 403 as pending and accepts string intervals" {
    var pending = TransportProbe{
        .expected_method = .post_json,
        .expected_url = codex.device_token_url,
        .expected_payload = "{\"device_auth_id\":\"dev-1\",\"user_code\":\"ABCD-1234\"}",
        .response_disposition = .rejected,
        .response_status = 403,
        .response_body = "",
    };
    var device = DeviceAuth{
        .device_auth_id = try std.testing.allocator.dupe(u8, "dev-1"),
        .user_code = try std.testing.allocator.dupe(u8, "ABCD-1234"),
        .interval_seconds = 5,
    };
    defer device.deinit(std.testing.allocator);
    try std.testing.expectEqual(PollOutcome.pending, try pollDeviceAuthorization(
        std.testing.allocator,
        pending.provider(),
        device,
    ));
    try std.testing.expect(pending.matched);

    var complete = TransportProbe{
        .expected_method = .post_json,
        .expected_url = codex.device_token_url,
        .expected_payload = "{\"device_auth_id\":\"dev-1\",\"user_code\":\"ABCD-1234\"}",
        .response_body = "{\"authorization_code\":\"auth-code\",\"code_verifier\":\"verifier\"}",
    };
    var outcome = try pollDeviceAuthorization(std.testing.allocator, complete.provider(), device);
    defer switch (outcome) {
        .success => |*code| code.deinit(std.testing.allocator),
        else => {},
    };
    try std.testing.expect(complete.matched);
    try std.testing.expectEqualStrings("auth-code", outcome.success.authorization_code);
}

test "Codex token exchange posts the authorization-code grant" {
    var probe = TransportProbe{
        .expected_method = .post_form,
        .expected_url = codex.token_url,
        .expected_payload = "grant_type=authorization_code&client_id=app_EMoamEEZ73f0CkXaXp7hrann&code=auth-code&code_verifier=verifier&redirect_uri=https%3A%2F%2Fauth.openai.com%2Fdeviceauth%2Fcallback",
        .response_body = "{\"access_token\":\"access\",\"refresh_token\":\"refresh\",\"expires_in\":1800,\"token_type\":\"Bearer\"}",
    };
    var token = try exchangeAuthorizationCode(
        std.testing.allocator,
        probe.provider(),
        "auth-code",
        "verifier",
        codex.device_redirect_uri,
    );
    defer token.deinit(std.testing.allocator);
    try std.testing.expect(probe.matched);
    try std.testing.expectEqualStrings("access", token.access_token);
    try std.testing.expectEqualStrings("refresh", token.refresh_token.?);
    try std.testing.expectEqual(@as(i64, 1800), token.expires_in);
}

test "Codex refresh keeps the previous refresh token" {
    var probe = TransportProbe{
        .expected_method = .post_form,
        .expected_url = codex.token_url,
        .expected_payload = "grant_type=refresh_token&refresh_token=old-refresh&client_id=app_EMoamEEZ73f0CkXaXp7hrann",
        .response_body = "{\"access_token\":\"fresh\",\"expires_in\":900,\"token_type\":\"Bearer\"}",
    };
    var token = try refreshToken(std.testing.allocator, probe.provider(), "old-refresh");
    defer token.deinit(std.testing.allocator);
    try std.testing.expect(probe.matched);
    try std.testing.expectEqualStrings("fresh", token.access_token);
    try std.testing.expectEqualStrings("old-refresh", token.refresh_token.?);
}

test "Codex account id is read from the ChatGPT JWT claim" {
    const payload = "{\"https://api.openai.com/auth\":{\"chatgpt_account_id\":\"acct_123\"}}";
    const encoded = try encodeJwt(std.testing.allocator, payload);
    defer std.testing.allocator.free(encoded);
    const token = try std.fmt.allocPrint(std.testing.allocator, "aaa.{s}.bbb", .{encoded});
    defer std.testing.allocator.free(token);
    const account_id = try accountIdFromAccessToken(std.testing.allocator, token);
    defer std.testing.allocator.free(account_id);
    try std.testing.expectEqualStrings("acct_123", account_id);
}
