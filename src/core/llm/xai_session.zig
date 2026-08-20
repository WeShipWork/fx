const std = @import("std");
const debug_trace = @import("../shared/debug_trace.zig");
const host_target = @import("../hosts/target.zig");
const io_mod = @import("../shared/io.zig");
const oauth = @import("../auth/oauth.zig");
const profile_paths = @import("../shared/profile_paths.zig");
const secret = @import("../auth/secret.zig");
const xai = @import("xai.zig");
const xai_oauth = @import("xai_oauth.zig");
const oauth_transport = @import("../auth/oauth_transport.zig");

const Allocator = std.mem.Allocator;

pub const auth_file_name = profile_paths.xai_auth_file_name;
const schema_version: i64 = 1;
const max_auth_file_bytes: usize = 64 * 1024;
const mutation_lock_file_name = "xai-auth.lock";
const mutation_lock_deadline_ms: u64 = 2000;

pub const Session = struct {
    issuer: []u8,
    client_id: []u8,
    access_token: []u8,
    refresh_token: []u8,
    expires_at_ms: i64,
    scope: []u8,
    token_type: []u8,

    pub fn deinit(self: *Session, alloc: Allocator) void {
        alloc.free(self.issuer);
        alloc.free(self.client_id);
        secret.zeroAndFree(alloc, self.access_token);
        secret.zeroAndFree(alloc, self.refresh_token);
        alloc.free(self.scope);
        alloc.free(self.token_type);
        self.* = undefined;
    }

    pub fn expired(self: Session, now_ms: i64) bool {
        return self.expires_at_ms -| xai.refresh_skew_ms <= now_ms;
    }
};

pub const DeleteOutcome = enum {
    deleted,
    missing,
    deleted_not_durable,
};

pub fn sessionFromTokenSet(
    alloc: Allocator,
    token: *oauth.TokenSet,
    now_ms: i64,
) !Session {
    const refresh_token = token.refresh_token orelse return error.NoRefreshToken;
    const expires_at_ms = try oauth.expiry_timestamp_ms(now_ms, token.expires_in);
    const issuer = try alloc.dupe(u8, xai.issuer);
    errdefer alloc.free(issuer);
    const client_id = try alloc.dupe(u8, xai.client_id);
    errdefer alloc.free(client_id);
    const session = Session{
        .issuer = issuer,
        .client_id = client_id,
        .access_token = token.access_token,
        .refresh_token = refresh_token,
        .expires_at_ms = expires_at_ms,
        .scope = token.scope,
        .token_type = token.token_type,
    };
    token.access_token = &.{};
    token.refresh_token = null;
    token.scope = &.{};
    token.token_type = &.{};
    return session;
}

pub fn parse(alloc: Allocator, bytes: []const u8) !Session {
    var parsed = try std.json.parseFromSlice(std.json.Value, alloc, bytes, .{});
    defer parsed.deinit();
    if (parsed.value != .object) return error.InvalidAuthSession;
    const object = parsed.value.object;
    const version = object.get("version") orelse return error.InvalidAuthSession;
    if (version != .integer or version.integer != schema_version) return error.InvalidAuthSession;
    const provider = try requiredString(object, "provider");
    if (!std.mem.eql(u8, provider, xai.provider_id)) return error.InvalidAuthSession;
    const saved_issuer = try requiredString(object, "issuer");
    if (!std.mem.eql(u8, saved_issuer, xai.issuer)) return error.InvalidAuthSession;

    const issuer = try alloc.dupe(u8, saved_issuer);
    errdefer alloc.free(issuer);
    const client_id = try dupeRequiredString(alloc, object, "client_id");
    errdefer alloc.free(client_id);
    const access_token = try dupeRequiredString(alloc, object, "access_token");
    errdefer secret.zeroAndFree(alloc, access_token);
    const refresh_token = try dupeRequiredString(alloc, object, "refresh_token");
    errdefer secret.zeroAndFree(alloc, refresh_token);
    const scope = try dupeRequiredString(alloc, object, "scope");
    errdefer alloc.free(scope);
    const token_type = try dupeRequiredString(alloc, object, "token_type");
    errdefer alloc.free(token_type);
    return .{
        .issuer = issuer,
        .client_id = client_id,
        .access_token = access_token,
        .refresh_token = refresh_token,
        .expires_at_ms = try requiredInteger(object, "expires_at_ms"),
        .scope = scope,
        .token_type = token_type,
    };
}

pub fn stringify(alloc: Allocator, session: Session) ![]u8 {
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit();
    const writer = &out.writer;
    try writer.writeAll("{\"version\":1");
    try writeField(writer, "provider", xai.provider_id);
    try writeField(writer, "issuer", session.issuer);
    try writeField(writer, "client_id", session.client_id);
    try writeField(writer, "access_token", session.access_token);
    try writeField(writer, "refresh_token", session.refresh_token);
    try writer.print(",\"expires_at_ms\":{d}", .{session.expires_at_ms});
    try writeField(writer, "scope", session.scope);
    try writeField(writer, "token_type", session.token_type);
    try writer.writeAll("}\n");
    return out.toOwnedSlice();
}

pub fn load(alloc: Allocator) !?Session {
    if (comptime host_target.is_wasm) return null;
    return loadNative(alloc);
}

pub fn hasPersistedSession(alloc: Allocator) bool {
    var session = (load(alloc) catch return false) orelse return false;
    session.deinit(alloc);
    return true;
}

pub fn saveNewSession(alloc: Allocator, session: Session) !void {
    if (comptime host_target.is_wasm) return error.Unsupported;
    var mutation = try beginMutation();
    defer mutation.deinit();
    try mutation.save(alloc, session);
}

pub fn deleteSession() !DeleteOutcome {
    if (comptime host_target.is_wasm) return .missing;
    var mutation = (try beginExistingMutation()) orelse return .missing;
    defer mutation.deinit();
    return mutation.delete();
}

fn isUnrecoverableRefreshError(err: anyerror) bool {
    return err == error.AccessDenied or
        err == error.ExpiredToken or
        err == error.InvalidClient or
        err == error.InvalidOAuthResponse or
        err == error.OAuthRequestFailed or
        err == error.NoRefreshToken;
}

pub fn loadValidAccessToken(
    alloc: Allocator,
    transport: oauth_transport.Provider,
    now_ms: i64,
) !?[]u8 {
    if (comptime host_target.is_wasm) return null;

    var refresh_token: ?[]u8 = null;
    defer if (refresh_token) |value| secret.zeroAndFree(alloc, value);

    {
        var mutation = (try beginExistingMutation()) orelse return null;
        defer mutation.deinit();
        var session = (try mutation.load(alloc)) orelse return null;
        defer session.deinit(alloc);
        if (!session.expired(now_ms)) {
            return try alloc.dupe(u8, session.access_token);
        }
        refresh_token = try alloc.dupe(u8, session.refresh_token);
    }

    var token = xai_oauth.refreshToken(alloc, transport, refresh_token.?) catch |err| {
        if (isUnrecoverableRefreshError(err)) {
            invalidateRejectedSession(alloc, refresh_token.?) catch {};
        }
        return err;
    };
    defer token.deinit(alloc);

    var refreshed = try sessionFromTokenSet(alloc, &token, io_mod.milliTimestamp());
    defer refreshed.deinit(alloc);

    if (beginExistingMutation()) |maybe_mutation| {
        if (maybe_mutation) |*mutation| {
            defer mutation.deinit();
            if (try mutation.load(alloc)) |*current| {
                defer current.deinit(alloc);
                if (!current.expired(io_mod.milliTimestamp()) and
                    current.expires_at_ms >= refreshed.expires_at_ms)
                {
                    return try alloc.dupe(u8, current.access_token);
                }
            }
            try mutation.save(alloc, refreshed);
        } else {
            try saveNewSession(alloc, refreshed);
        }
    } else |_| {}

    return try alloc.dupe(u8, refreshed.access_token);
}

fn invalidateRejectedSession(alloc: Allocator, rejected_refresh: []const u8) !void {
    if (beginExistingMutation()) |maybe_mutation| {
        if (maybe_mutation) |*mutation| {
            defer mutation.deinit();
            try deleteMatchingRefresh(&mutation.fx_dir.dir, alloc, rejected_refresh);
            return;
        }
    } else |_| {}

    const home = io_mod.getenv("HOME") orelse return error.HomeNotSet;
    var home_dir = try std.Io.Dir.openDirAbsolute(io_mod.getIo(), home, .{ .iterate = true });
    defer home_dir.close(io_mod.getIo());
    var fx_dir = home_dir.openDir(io_mod.getIo(), profile_paths.root_dir_name, .{
        .iterate = true,
        .follow_symlinks = false,
    }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer fx_dir.close(io_mod.getIo());
    try invalidateMatchingRefreshInPlace(&fx_dir, alloc, rejected_refresh);
}

fn deleteMatchingRefresh(fx_dir: *std.Io.Dir, alloc: Allocator, rejected_refresh: []const u8) !void {
    var session = (try loadFromDir(alloc, fx_dir)) orelse return;
    defer session.deinit(alloc);
    if (!std.mem.eql(u8, session.refresh_token, rejected_refresh)) return;
    fx_dir.deleteFile(io_mod.getIo(), auth_file_name) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
}

fn invalidateMatchingRefreshInPlace(fx_dir: *std.Io.Dir, alloc: Allocator, rejected_refresh: []const u8) !void {
    var file = fx_dir.openFile(io_mod.getIo(), auth_file_name, .{
        .mode = .read_write,
        .allow_directory = false,
        .follow_symlinks = false,
        .resolve_beneath = true,
    }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer file.close(io_mod.getIo());
    try invalidateOpenFileIfRefreshMatches(&file, alloc, rejected_refresh);
}

fn invalidateOpenFileIfRefreshMatches(
    file: *std.Io.File,
    alloc: Allocator,
    rejected_refresh: []const u8,
) !void {
    const bytes = io_mod.readFileToEnd(alloc, file, max_auth_file_bytes) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return,
    };
    defer secret.zeroAndFree(alloc, bytes);
    var session = parse(alloc, bytes) catch return;
    defer session.deinit(alloc);
    if (!std.mem.eql(u8, session.refresh_token, rejected_refresh)) return;
    try file.setLength(io_mod.getIo(), 0);
}

const NativeMutation = struct {
    fx_dir: io_mod.VerifiedDir,
    lock: io_mod.TimedAdvisoryLock,

    pub fn deinit(self: *NativeMutation) void {
        self.lock.release();
        self.fx_dir.close();
        self.* = undefined;
    }

    pub fn load(self: *NativeMutation, alloc: Allocator) !?Session {
        return loadFromDir(alloc, &self.fx_dir.dir);
    }

    pub fn save(self: *NativeMutation, alloc: Allocator, session: Session) !void {
        const text = try stringify(alloc, session);
        defer secret.zeroAndFree(alloc, text);
        try io_mod.durableReplaceVerified(alloc, &self.fx_dir, auth_file_name, text);
    }

    pub fn delete(self: *NativeMutation) !DeleteOutcome {
        self.fx_dir.dir.deleteFile(io_mod.getIo(), auth_file_name) catch |err| switch (err) {
            error.FileNotFound => return .missing,
            else => return err,
        };
        return .deleted;
    }
};

const Mutation = NativeMutation;

fn beginMutation() !Mutation {
    const home = io_mod.getenv("HOME") orelse return error.HomeNotSet;
    var home_dir = io_mod.VerifiedDir{
        .dir = try std.Io.Dir.openDirAbsolute(io_mod.getIo(), home, .{ .iterate = true }),
    };
    defer home_dir.close();
    const fx_dir = try io_mod.openOrCreateVerifiedPrivateDir(&home_dir, profile_paths.root_dir_name);
    return lockMutation(fx_dir);
}

fn beginExistingMutation() !?Mutation {
    const home = io_mod.getenv("HOME") orelse return error.HomeNotSet;
    var home_dir = io_mod.VerifiedDir{
        .dir = try std.Io.Dir.openDirAbsolute(io_mod.getIo(), home, .{ .iterate = true }),
    };
    defer home_dir.close();
    const fx_dir = io_mod.openOrCreateVerifiedPrivateDir(&home_dir, profile_paths.root_dir_name) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    return @as(?Mutation, try lockMutation(fx_dir));
}

fn lockMutation(open_fx_dir: io_mod.VerifiedDir) !Mutation {
    var fx_dir = open_fx_dir;
    errdefer fx_dir.close();
    const lock = try io_mod.acquireTimedAdvisoryLock(&fx_dir, mutation_lock_file_name, mutation_lock_deadline_ms);
    return .{
        .fx_dir = fx_dir,
        .lock = lock,
    };
}

fn loadNative(alloc: Allocator) !?Session {
    const home = io_mod.getenv("HOME") orelse return null;
    var home_dir = std.Io.Dir.openDirAbsolute(io_mod.getIo(), home, .{ .iterate = true }) catch return null;
    defer home_dir.close(io_mod.getIo());
    var fx_dir = home_dir.openDir(io_mod.getIo(), profile_paths.root_dir_name, .{
        .iterate = true,
        .follow_symlinks = false,
    }) catch return null;
    defer fx_dir.close(io_mod.getIo());
    return loadFromDir(alloc, &fx_dir);
}

fn loadFromDir(alloc: Allocator, fx_dir: *std.Io.Dir) !?Session {
    var file = fx_dir.openFile(io_mod.getIo(), auth_file_name, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
        .resolve_beneath = true,
    }) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => {
            debug_trace.logf("auth", "xai session load failed step=open_file err={s}", .{@errorName(err)});
            return null;
        },
    };
    defer file.close(io_mod.getIo());
    const bytes = try io_mod.readFileToEnd(alloc, &file, max_auth_file_bytes);
    defer secret.zeroAndFree(alloc, bytes);
    return parse(alloc, bytes) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => {
            debug_trace.logf("auth", "xai session load failed step=parse err={s}", .{@errorName(err)});
            return null;
        },
    };
}

fn writeField(writer: *std.Io.Writer, name: []const u8, value: []const u8) !void {
    try writer.writeAll(",");
    try std.json.Stringify.value(name, .{}, writer);
    try writer.writeAll(":");
    try std.json.Stringify.value(value, .{}, writer);
}

fn dupeRequiredString(alloc: Allocator, object: std.json.ObjectMap, key: []const u8) ![]u8 {
    return alloc.dupe(u8, try requiredString(object, key));
}

fn requiredString(object: std.json.ObjectMap, key: []const u8) ![]const u8 {
    const value = object.get(key) orelse return error.InvalidAuthSession;
    if (value != .string or value.string.len == 0) return error.InvalidAuthSession;
    return value.string;
}

fn requiredInteger(object: std.json.ObjectMap, key: []const u8) !i64 {
    const value = object.get(key) orelse return error.InvalidAuthSession;
    if (value != .integer) return error.InvalidAuthSession;
    return value.integer;
}

test "xAI session stringifies and parses" {
    var session = Session{
        .issuer = try std.testing.allocator.dupe(u8, xai.issuer),
        .client_id = try std.testing.allocator.dupe(u8, xai.client_id),
        .access_token = try std.testing.allocator.dupe(u8, "access"),
        .refresh_token = try std.testing.allocator.dupe(u8, "refresh"),
        .expires_at_ms = 1234,
        .scope = try std.testing.allocator.dupe(u8, xai.scope),
        .token_type = try std.testing.allocator.dupe(u8, "Bearer"),
    };
    defer session.deinit(std.testing.allocator);

    const text = try stringify(std.testing.allocator, session);
    defer secret.zeroAndFree(std.testing.allocator, text);
    var parsed = try parse(std.testing.allocator, text);
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings(xai.issuer, parsed.issuer);
    try std.testing.expectEqualStrings("access", parsed.access_token);
    try std.testing.expectEqualStrings("refresh", parsed.refresh_token);
    try std.testing.expectEqual(@as(i64, 1234), parsed.expires_at_ms);
}

test "xAI session rejects another provider" {
    try std.testing.expectError(
        error.InvalidAuthSession,
        parse(std.testing.allocator, "{\"version\":1,\"provider\":\"vercel\",\"issuer\":\"https://auth.x.ai\",\"client_id\":\"c\",\"access_token\":\"a\",\"refresh_token\":\"r\",\"expires_at_ms\":1,\"scope\":\"s\",\"token_type\":\"Bearer\"}"),
    );
}

test "xAI rejected refresh deletes only the matching session file" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var session = Session{
        .issuer = try std.testing.allocator.dupe(u8, xai.issuer),
        .client_id = try std.testing.allocator.dupe(u8, xai.client_id),
        .access_token = try std.testing.allocator.dupe(u8, "access"),
        .refresh_token = try std.testing.allocator.dupe(u8, "dead-refresh"),
        .expires_at_ms = 1,
        .scope = try std.testing.allocator.dupe(u8, xai.scope),
        .token_type = try std.testing.allocator.dupe(u8, "Bearer"),
    };
    defer session.deinit(std.testing.allocator);
    const text = try stringify(std.testing.allocator, session);
    defer secret.zeroAndFree(std.testing.allocator, text);
    {
        var file = try tmp.dir.createFile(std.testing.io, auth_file_name, .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, text);
    }

    try deleteMatchingRefresh(&tmp.dir, std.testing.allocator, "other-refresh");
    var kept = (try loadFromDir(std.testing.allocator, &tmp.dir)).?;
    kept.deinit(std.testing.allocator);

    try deleteMatchingRefresh(&tmp.dir, std.testing.allocator, "dead-refresh");
    try std.testing.expect((try loadFromDir(std.testing.allocator, &tmp.dir)) == null);
}

test "xAI unlocked invalidation keeps a replaced session" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var rejected = Session{
        .issuer = try std.testing.allocator.dupe(u8, xai.issuer),
        .client_id = try std.testing.allocator.dupe(u8, xai.client_id),
        .access_token = try std.testing.allocator.dupe(u8, "old-access"),
        .refresh_token = try std.testing.allocator.dupe(u8, "dead-refresh"),
        .expires_at_ms = 1,
        .scope = try std.testing.allocator.dupe(u8, xai.scope),
        .token_type = try std.testing.allocator.dupe(u8, "Bearer"),
    };
    defer rejected.deinit(std.testing.allocator);
    const rejected_text = try stringify(std.testing.allocator, rejected);
    defer secret.zeroAndFree(std.testing.allocator, rejected_text);
    {
        var file = try tmp.dir.createFile(std.testing.io, auth_file_name, .{});
        defer file.close(std.testing.io);
        try file.writeStreamingAll(std.testing.io, rejected_text);
    }

    var opened = try tmp.dir.openFile(std.testing.io, auth_file_name, .{
        .mode = .read_write,
        .allow_directory = false,
        .follow_symlinks = false,
        .resolve_beneath = true,
    });
    defer opened.close(std.testing.io);

    var replacement = Session{
        .issuer = try std.testing.allocator.dupe(u8, xai.issuer),
        .client_id = try std.testing.allocator.dupe(u8, xai.client_id),
        .access_token = try std.testing.allocator.dupe(u8, "new-access"),
        .refresh_token = try std.testing.allocator.dupe(u8, "live-refresh"),
        .expires_at_ms = 9_999,
        .scope = try std.testing.allocator.dupe(u8, xai.scope),
        .token_type = try std.testing.allocator.dupe(u8, "Bearer"),
    };
    defer replacement.deinit(std.testing.allocator);
    const replacement_text = try stringify(std.testing.allocator, replacement);
    defer secret.zeroAndFree(std.testing.allocator, replacement_text);
    {
        var temp = try tmp.dir.createFile(std.testing.io, ".xai-auth.tmp", .{ .exclusive = true });
        defer temp.close(std.testing.io);
        try temp.writeStreamingAll(std.testing.io, replacement_text);
    }
    try tmp.dir.rename(".xai-auth.tmp", tmp.dir, auth_file_name, std.testing.io);

    try invalidateOpenFileIfRefreshMatches(&opened, std.testing.allocator, "dead-refresh");
    var kept = (try loadFromDir(std.testing.allocator, &tmp.dir)).?;
    defer kept.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("live-refresh", kept.refresh_token);
}

test "xAI rejected refresh errors discard the persisted session" {
    try std.testing.expect(isUnrecoverableRefreshError(error.AccessDenied));
    try std.testing.expect(isUnrecoverableRefreshError(error.ExpiredToken));
    try std.testing.expect(isUnrecoverableRefreshError(error.InvalidClient));
    try std.testing.expect(isUnrecoverableRefreshError(error.InvalidOAuthResponse));
    try std.testing.expect(isUnrecoverableRefreshError(error.OAuthRequestFailed));
    try std.testing.expect(isUnrecoverableRefreshError(error.NoRefreshToken));
    try std.testing.expect(!isUnrecoverableRefreshError(error.HomeNotSet));
    try std.testing.expect(!isUnrecoverableRefreshError(error.LockBusy));
}

test "xAI session expires with refresh skew" {
    const session = Session{
        .issuer = undefined,
        .client_id = undefined,
        .access_token = undefined,
        .refresh_token = undefined,
        .expires_at_ms = 10_000,
        .scope = undefined,
        .token_type = undefined,
    };
    try std.testing.expect(session.expired(10_000));
    try std.testing.expect(session.expired(10_000 - xai.refresh_skew_ms));
    try std.testing.expect(!session.expired(10_000 - xai.refresh_skew_ms - 1));
}
