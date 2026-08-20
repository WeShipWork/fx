const std = @import("std");
const oauth = @import("../auth/oauth.zig");
const oauth_transport = @import("../auth/oauth_transport.zig");
const secret = @import("../auth/secret.zig");
const xai = @import("xai.zig");

const Allocator = std.mem.Allocator;

pub fn metadata(alloc: Allocator) !oauth.Metadata {
    const issuer = try alloc.dupe(u8, xai.issuer);
    errdefer alloc.free(issuer);
    const device_authorization_endpoint = try alloc.dupe(u8, xai.device_code_url);
    errdefer alloc.free(device_authorization_endpoint);
    const token_endpoint = try alloc.dupe(u8, xai.token_url);
    errdefer alloc.free(token_endpoint);
    return .{
        .issuer = issuer,
        .device_authorization_endpoint = device_authorization_endpoint,
        .token_endpoint = token_endpoint,
    };
}

pub fn requestDeviceAuthorization(
    alloc: Allocator,
    transport: oauth_transport.Provider,
) !oauth.DeviceAuthorization {
    var form: FormBody = .{};
    var writer: std.Io.Writer.Allocating = .init(alloc);
    defer writer.deinit();
    try form.append(&writer.writer, "client_id", xai.client_id);
    try form.append(&writer.writer, "scope", xai.scope);
    try form.append(&writer.writer, "referrer", xai.referrer);

    var response = try transport.execute(alloc, .{
        .method = .post_form,
        .url = xai.device_code_url,
        .payload = writer.written(),
    });
    defer response.deinit(alloc);
    if (response.disposition != .accepted) {
        try mapRejected(alloc, response.body);
        return oauth.OAuthError.OAuthRequestFailed;
    }

    const body = response.takeBody();
    defer secret.zeroAndFree(alloc, body);
    var device = try oauth.parseDeviceAuthorization(alloc, body);
    errdefer device.deinit(alloc);
    try validateVerificationUri(device.verification_uri);
    if (device.verification_uri_complete) |complete| try validateVerificationUri(complete);
    return device;
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
            else => xai.default_token_lifetime_seconds,
        }
    else
        xai.default_token_lifetime_seconds;
    if (expires_in <= 0) return oauth.OAuthError.InvalidOAuthResponse;

    return .{
        .access_token = access_token,
        .refresh_token = refresh_token,
        .expires_in = expires_in,
        .scope = scope,
        .token_type = token_type,
    };
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
    try form.append(&writer.writer, "client_id", xai.client_id);
    try form.append(&writer.writer, "refresh_token", refresh_token);

    var response = try transport.execute(alloc, .{
        .method = .post_form,
        .url = xai.token_url,
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

fn validateVerificationUri(raw: []const u8) !void {
    const uri = std.Uri.parse(raw) catch return oauth.OAuthError.InvalidOAuthResponse;
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "https")) return oauth.OAuthError.InvalidOAuthResponse;
}

fn mapRejected(alloc: Allocator, body: []const u8) !void {
    var parsed = std.json.parseFromSlice(std.json.Value, alloc, body, .{}) catch
        return oauth.OAuthError.OAuthRequestFailed;
    defer parsed.deinit();
    if (parsed.value != .object) return oauth.OAuthError.OAuthRequestFailed;
    const value = parsed.value.object.get("error") orelse return oauth.OAuthError.OAuthRequestFailed;
    if (value != .string) return oauth.OAuthError.OAuthRequestFailed;
    if (std.mem.eql(u8, value.string, "authorization_pending")) return oauth.OAuthError.AuthorizationPending;
    if (std.mem.eql(u8, value.string, "slow_down")) return oauth.OAuthError.SlowDown;
    if (std.mem.eql(u8, value.string, "access_denied") or
        std.mem.eql(u8, value.string, "authorization_denied"))
        return oauth.OAuthError.AccessDenied;
    if (std.mem.eql(u8, value.string, "expired_token")) return oauth.OAuthError.ExpiredToken;
    if (std.mem.eql(u8, value.string, "invalid_client")) return oauth.OAuthError.InvalidClient;
    return oauth.OAuthError.OAuthRequestFailed;
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
    expected_url: []const u8,
    expected_payload: []const u8,
    response_disposition: oauth_transport.Disposition = .accepted,
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
        self.matched = request.method == .post_form and
            std.mem.eql(u8, request.url, self.expected_url) and
            request.payload != null and
            std.mem.eql(u8, request.payload.?, self.expected_payload);
        return .{
            .disposition = self.response_disposition,
            .body = try alloc.dupe(u8, self.response_body),
        };
    }
};

test "xAI device authorization posts scope and referrer" {
    var probe = TransportProbe{
        .expected_url = xai.device_code_url,
        .expected_payload = "client_id=b1a00492-073a-47ea-816f-4c329264a828&scope=openid%20profile%20email%20offline_access%20grok-cli%3Aaccess%20api%3Aaccess&referrer=fx",
        .response_body = "{\"device_code\":\"device\",\"user_code\":\"ABCD-1234\",\"verification_uri\":\"https://auth.x.ai/activate\",\"expires_in\":600,\"interval\":5}",
    };
    var device = try requestDeviceAuthorization(std.testing.allocator, probe.provider());
    defer device.deinit(std.testing.allocator);
    try std.testing.expect(probe.matched);
    try std.testing.expectEqualStrings("ABCD-1234", device.user_code);
}

test "xAI device authorization rejects a non-https verification URI" {
    var probe = TransportProbe{
        .expected_url = xai.device_code_url,
        .expected_payload = "client_id=b1a00492-073a-47ea-816f-4c329264a828&scope=openid%20profile%20email%20offline_access%20grok-cli%3Aaccess%20api%3Aaccess&referrer=fx",
        .response_body = "{\"device_code\":\"device\",\"user_code\":\"ABCD-1234\",\"verification_uri\":\"http://evil.test/activate\",\"expires_in\":600,\"interval\":5}",
    };
    try std.testing.expectError(
        oauth.OAuthError.InvalidOAuthResponse,
        requestDeviceAuthorization(std.testing.allocator, probe.provider()),
    );
}

test "xAI token parse keeps the previous refresh token and defaults expiry" {
    var token = try parseTokenSet(
        std.testing.allocator,
        "{\"access_token\":\"next-access\"}",
        "kept-refresh",
    );
    defer token.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("next-access", token.access_token);
    try std.testing.expectEqualStrings("kept-refresh", token.refresh_token.?);
    try std.testing.expectEqual(@as(i64, xai.default_token_lifetime_seconds), token.expires_in);
    try std.testing.expectEqualStrings("Bearer", token.token_type);
}

test "xAI refresh posts the refresh grant" {
    var probe = TransportProbe{
        .expected_url = xai.token_url,
        .expected_payload = "grant_type=refresh_token&client_id=b1a00492-073a-47ea-816f-4c329264a828&refresh_token=old-refresh",
        .response_body = "{\"access_token\":\"fresh\",\"refresh_token\":\"rotated\",\"expires_in\":1800,\"token_type\":\"Bearer\"}",
    };
    var token = try refreshToken(std.testing.allocator, probe.provider(), "old-refresh");
    defer token.deinit(std.testing.allocator);
    try std.testing.expect(probe.matched);
    try std.testing.expectEqualStrings("fresh", token.access_token);
    try std.testing.expectEqualStrings("rotated", token.refresh_token.?);
    try std.testing.expectEqual(@as(i64, 1800), token.expires_in);
}
