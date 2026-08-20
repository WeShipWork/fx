const std = @import("std");

pub const provider_id = "xai";
pub const model_id = "grok-4.6";
pub const model_ref = provider_id ++ "/" ++ model_id;
pub const issuer = "https://auth.x.ai";
pub const client_id = "b1a00492-073a-47ea-816f-4c329264a828";
pub const scope = "openid profile email offline_access grok-cli:access api:access";
pub const referrer = "fx";
pub const device_code_url = "https://auth.x.ai/oauth2/device/code";
pub const token_url = "https://auth.x.ai/oauth2/token";
pub const api_base_url = "https://api.x.ai/v1";
pub const chat_completions_url = api_base_url ++ "/chat/completions";
pub const default_token_lifetime_seconds: i64 = 3600;
pub const refresh_skew_ms: i64 = 5 * 60 * 1000;

pub fn isXaiModel(model: []const u8) bool {
    return std.mem.eql(u8, model, model_ref) or std.mem.eql(u8, model, model_id);
}

pub fn wireModelId(model: []const u8) []const u8 {
    if (std.mem.eql(u8, model, model_ref)) return model_id;
    return model;
}

/// xAI models authenticate with the xAI session, not Vercel AI Gateway.
pub fn promptCredentialSatisfied(model: []const u8, has_gateway: bool, has_xai_session: bool) bool {
    if (isXaiModel(model)) return has_xai_session;
    return has_gateway;
}

test "xAI identity accepts the canonical ref and the wire id" {
    try std.testing.expect(isXaiModel(model_ref));
    try std.testing.expect(isXaiModel(model_id));
    try std.testing.expect(!isXaiModel("xai/grok-4.5"));
    try std.testing.expect(!isXaiModel("vercel-ai-gateway/xai/grok-4.6"));
    try std.testing.expectEqualStrings(model_id, wireModelId(model_ref));
    try std.testing.expectEqualStrings(model_id, wireModelId(model_id));
}

test "xAI models need an xAI session, not a Gateway credential" {
    try std.testing.expect(promptCredentialSatisfied(model_ref, false, true));
    try std.testing.expect(!promptCredentialSatisfied(model_ref, true, false));
    try std.testing.expect(promptCredentialSatisfied("zai/glm-5.2", true, false));
    try std.testing.expect(!promptCredentialSatisfied("zai/glm-5.2", false, true));
}
