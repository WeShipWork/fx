const std = @import("std");
const model_catalog = @import("../gateway/model_catalog.zig");
const codex = @import("codex.zig");

const Allocator = std.mem.Allocator;

pub fn containsId(entries: []const model_catalog.ModelCatalogEntry, id: []const u8) bool {
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.id, id)) return true;
    }
    return false;
}

pub fn containsModelId(ids: []const []const u8, id: []const u8) bool {
    for (ids) |candidate| {
        if (std.mem.eql(u8, candidate, id)) return true;
    }
    return false;
}

pub fn appendEntries(alloc: Allocator, entries: *std.ArrayList(model_catalog.ModelCatalogEntry)) !void {
    for (codex.models) |spec| {
        const id = try std.fmt.allocPrint(alloc, "{s}/{s}", .{ codex.provider_id, spec.id });
        errdefer alloc.free(id);
        if (containsId(entries.items, id)) {
            alloc.free(id);
            continue;
        }
        const model_type = try alloc.dupe(u8, "language");
        errdefer alloc.free(model_type);
        entries.append(alloc, .{
            .id = id,
            .model_type = model_type,
            .released = 200,
            .has_tool_use = true,
            .has_reasoning = true,
            .has_vision = true,
            .context_window = spec.context_window,
            .max_tokens = 128_000,
        }) catch |err| {
            alloc.free(model_type);
            alloc.free(id);
            return err;
        };
    }
}

pub fn appendModelIds(alloc: Allocator, ids: *std.ArrayList([]u8)) !void {
    for (codex.models) |spec| {
        const id = try std.fmt.allocPrint(alloc, "{s}/{s}", .{ codex.provider_id, spec.id });
        errdefer alloc.free(id);
        if (containsModelId(ids.items, id)) {
            alloc.free(id);
            continue;
        }
        ids.append(alloc, id) catch |err| {
            alloc.free(id);
            return err;
        };
    }
}

test "Codex catalog overlay adds prefixed models once" {
    var entries: std.ArrayList(model_catalog.ModelCatalogEntry) = .empty;
    defer model_catalog.freeModelCatalog(std.testing.allocator, &entries);

    try appendEntries(std.testing.allocator, &entries);
    const first_count = entries.items.len;
    try std.testing.expect(first_count >= codex.models.len);
    try std.testing.expect(containsId(entries.items, codex.default_model_ref));
    try std.testing.expect(containsId(entries.items, "openai-codex/gpt-5.6-sol"));

    try appendEntries(std.testing.allocator, &entries);
    try std.testing.expectEqual(first_count, entries.items.len);
}

test "Codex model id overlay skips duplicates" {
    var ids: std.ArrayList([]u8) = .empty;
    defer {
        for (ids.items) |id| std.testing.allocator.free(id);
        ids.deinit(std.testing.allocator);
    }

    try ids.append(std.testing.allocator, try std.testing.allocator.dupe(u8, codex.default_model_ref));
    try appendModelIds(std.testing.allocator, &ids);
    var defaults: usize = 0;
    for (ids.items) |id| {
        if (std.mem.eql(u8, id, codex.default_model_ref)) defaults += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), defaults);
    try std.testing.expect(containsModelId(ids.items, "openai-codex/gpt-5.5"));
}
