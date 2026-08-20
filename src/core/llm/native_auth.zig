const std = @import("std");
const codex = @import("codex.zig");
const xai = @import("xai.zig");

pub const missing_xai_session_message =
    "Fx needs an xAI session. Run fx login xai to sign in with SuperGrok or X Premium.";
pub const missing_codex_session_message =
    "Fx needs a Codex session. Run fx login codex to sign in with ChatGPT Plus or Pro.";

pub fn isNativeSubscriptionModel(model: []const u8) bool {
    return xai.isXaiModel(model) or codex.isCodexModel(model);
}

pub fn promptCredentialSatisfied(
    model: []const u8,
    has_gateway: bool,
    has_xai_session: bool,
    has_codex_session: bool,
) bool {
    if (xai.isXaiModel(model)) return has_xai_session;
    if (codex.isCodexModel(model)) return has_codex_session;
    return has_gateway;
}

pub fn missingSessionMessage(model: []const u8) ?[]const u8 {
    if (xai.isXaiModel(model)) return missing_xai_session_message;
    if (codex.isCodexModel(model)) return missing_codex_session_message;
    return null;
}

test "native subscription models do not accept a Gateway credential" {
    try std.testing.expect(isNativeSubscriptionModel(xai.model_ref));
    try std.testing.expect(isNativeSubscriptionModel(codex.default_model_ref));
    try std.testing.expect(!isNativeSubscriptionModel("openai/gpt-5.4"));

    try std.testing.expect(promptCredentialSatisfied(xai.model_ref, true, true, false));
    try std.testing.expect(!promptCredentialSatisfied(xai.model_ref, true, false, true));
    try std.testing.expect(promptCredentialSatisfied(codex.default_model_ref, true, false, true));
    try std.testing.expect(!promptCredentialSatisfied(codex.default_model_ref, true, true, false));
    try std.testing.expect(promptCredentialSatisfied("zai/glm-5.2", true, false, false));
    try std.testing.expect(!promptCredentialSatisfied("zai/glm-5.2", false, true, true));
}

test "missing session copy is provider-specific" {
    try std.testing.expectEqualStrings(missing_xai_session_message, missingSessionMessage(xai.model_ref).?);
    try std.testing.expectEqualStrings(missing_codex_session_message, missingSessionMessage(codex.default_model_ref).?);
    try std.testing.expect(missingSessionMessage("zai/glm-5.2") == null);
}
