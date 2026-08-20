const std = @import("std");

pub const provider_id = "openai-codex";
pub const default_model_id = "gpt-5.4";
pub const default_model_ref = provider_id ++ "/" ++ default_model_id;
pub const issuer = "https://auth.openai.com";
pub const client_id = "app_EMoamEEZ73f0CkXaXp7hrann";
pub const scope = "openid profile email offline_access api.connectors.read api.connectors.invoke";
pub const originator = "fx";
pub const authorize_url = issuer ++ "/oauth/authorize";
pub const token_url = issuer ++ "/oauth/token";
pub const device_user_code_url = issuer ++ "/api/accounts/deviceauth/usercode";
pub const device_token_url = issuer ++ "/api/accounts/deviceauth/token";
pub const device_verification_uri = issuer ++ "/codex/device";
pub const device_redirect_uri = issuer ++ "/deviceauth/callback";
pub const api_base_url = "https://chatgpt.com/backend-api";
pub const responses_url = api_base_url ++ "/codex/responses";
pub const jwt_auth_claim = "https://api.openai.com/auth";
pub const default_token_lifetime_seconds: i64 = 3600;
pub const refresh_skew_ms: i64 = 5 * 60 * 1000;
pub const device_code_timeout_seconds: i64 = 15 * 60;

pub const ModelSpec = struct {
    id: []const u8,
    context_window: u32,
    supports_max_effort: bool,
};

pub const models = [_]ModelSpec{
    .{ .id = "gpt-5.4", .context_window = 272_000, .supports_max_effort = false },
    .{ .id = "gpt-5.4-mini", .context_window = 272_000, .supports_max_effort = false },
    .{ .id = "gpt-5.5", .context_window = 272_000, .supports_max_effort = false },
    .{ .id = "gpt-5.6-luna", .context_window = 272_000, .supports_max_effort = true },
    .{ .id = "gpt-5.6-sol", .context_window = 272_000, .supports_max_effort = true },
    .{ .id = "gpt-5.6-terra", .context_window = 272_000, .supports_max_effort = true },
    .{ .id = "gpt-5.3-codex-spark", .context_window = 128_000, .supports_max_effort = false },
    .{ .id = "gpt-daybreak-blue-latest", .context_window = 272_000, .supports_max_effort = true },
    .{ .id = "gpt-daybreak-red-latest", .context_window = 372_000, .supports_max_effort = true },
};

pub fn isCodexModel(model: []const u8) bool {
    return std.mem.startsWith(u8, model, provider_id ++ "/");
}

pub fn wireModelId(model: []const u8) []const u8 {
    const prefix = provider_id ++ "/";
    if (std.mem.startsWith(u8, model, prefix)) return model[prefix.len..];
    return model;
}

pub fn modelSpec(model: []const u8) ?ModelSpec {
    const wire_id = wireModelId(model);
    for (models) |spec| {
        if (std.mem.eql(u8, spec.id, wire_id)) return spec;
    }
    return null;
}

pub fn promptCredentialSatisfied(model: []const u8, has_gateway: bool, has_codex_session: bool) bool {
    if (isCodexModel(model)) return has_codex_session;
    return has_gateway;
}

test "Codex identity accepts only the openai-codex prefix" {
    try std.testing.expect(isCodexModel(default_model_ref));
    try std.testing.expect(isCodexModel("openai-codex/gpt-5.5"));
    try std.testing.expect(!isCodexModel("gpt-5.4"));
    try std.testing.expect(!isCodexModel("openai/gpt-5.4"));
    try std.testing.expect(!isCodexModel("xai/grok-4.6"));
    try std.testing.expectEqualStrings(default_model_id, wireModelId(default_model_ref));
    try std.testing.expectEqualStrings("gpt-5.5", wireModelId("openai-codex/gpt-5.5"));
}

test "Codex models need a Codex session, not a Gateway credential" {
    try std.testing.expect(promptCredentialSatisfied(default_model_ref, false, true));
    try std.testing.expect(!promptCredentialSatisfied(default_model_ref, true, false));
    try std.testing.expect(promptCredentialSatisfied("zai/glm-5.2", true, false));
    try std.testing.expect(!promptCredentialSatisfied("zai/glm-5.2", false, true));
}
