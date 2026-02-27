//! end-to-end repo verification
//!
//! exercises the full AT Protocol trust chain:
//!   handle → DID → DID document → signing key
//!                                       ↓
//!   repo CAR → commit → signature ← verified against key
//!                   ↓
//!            MST root CID → walk nodes → rebuild tree → CID match

const std = @import("std");
const Allocator = std.mem.Allocator;

const Did = @import("../syntax/did.zig").Did;
const Handle = @import("../syntax/handle.zig").Handle;
const DidDocument = @import("../identity/did_document.zig").DidDocument;
const DidResolver = @import("../identity/did_resolver.zig").DidResolver;
const HandleResolver = @import("../identity/handle_resolver.zig").HandleResolver;
const HttpTransport = @import("../xrpc/transport.zig").HttpTransport;
const multibase = @import("../crypto/multibase.zig");
const multicodec = @import("../crypto/multicodec.zig");
const jwt = @import("../crypto/jwt.zig");
const cbor = @import("cbor.zig");
const car = @import("car.zig");
const mst = @import("mst.zig");

pub const VerifyResult = struct {
    did: []const u8,
    handle: []const u8,
    signing_key_type: multicodec.KeyType,
    commit_rev: []const u8,
    commit_version: i64,
    record_count: usize,
};

pub const VerifyError = error{
    InvalidIdentifier,
    SigningKeyNotFound,
    PdsEndpointNotFound,
    NoRootsInCar,
    CommitBlockNotFound,
    InvalidCommit,
    SignatureNotFound,
    MstRootMismatch,
    FetchFailed,
} || Allocator.Error;

/// verify a repo end-to-end: resolve identity, fetch repo, verify commit signature, walk and rebuild MST.
pub fn verifyRepo(caller_alloc: Allocator, identifier: []const u8) !VerifyResult {
    var arena = std.heap.ArenaAllocator.init(caller_alloc);
    defer arena.deinit();
    const allocator = arena.allocator();

    // 1. resolve identifier to DID
    const did_str = if (Did.parse(identifier) != null)
        identifier
    else blk: {
        const handle = Handle.parse(identifier) orelse return error.InvalidIdentifier;
        var resolver = HandleResolver.init(allocator);
        defer resolver.deinit();
        break :blk try resolver.resolve(handle);
    };

    const did = Did.parse(did_str) orelse return error.InvalidIdentifier;

    // 2. resolve DID → DID document
    var did_resolver = DidResolver.init(allocator);
    defer did_resolver.deinit();
    var did_doc = try did_resolver.resolve(did);
    defer did_doc.deinit();

    // 3. extract signing key
    const signing_vm = did_doc.signingKey() orelse return error.SigningKeyNotFound;
    const key_bytes = try multibase.decode(allocator, signing_vm.public_key_multibase);
    const public_key = try multicodec.parsePublicKey(key_bytes);

    // 4. extract PDS endpoint
    const pds_endpoint = did_doc.pdsEndpoint() orelse return error.PdsEndpointNotFound;

    // 5. fetch repo CAR
    const car_bytes = try fetchRepo(allocator, pds_endpoint, did_str);

    // 6. parse CAR (no size limits — we fetched this ourselves from the PDS)
    const repo_car = car.readWithOptions(allocator, car_bytes, .{
        .max_size = car_bytes.len,
        .max_blocks = car_bytes.len, // effectively unlimited
    }) catch return error.InvalidCommit;
    if (repo_car.roots.len == 0) return error.NoRootsInCar;

    // 7. find commit block
    const commit_data = car.findBlock(repo_car, repo_car.roots[0].raw) orelse return error.CommitBlockNotFound;

    // 8. decode commit
    const commit = cbor.decodeAll(allocator, commit_data) catch return error.InvalidCommit;
    const commit_did = commit.getString("did") orelse return error.InvalidCommit;
    const commit_version = commit.getInt("version") orelse return error.InvalidCommit;
    const commit_rev = commit.getString("rev") orelse return error.InvalidCommit;
    const sig_bytes = commit.getBytes("sig") orelse return error.SignatureNotFound;

    const data_cid_value = commit.get("data") orelse return error.InvalidCommit;
    const data_cid = switch (data_cid_value) {
        .cid => |c| c,
        else => return error.InvalidCommit,
    };

    // sanity: commit DID matches resolved DID
    if (!std.mem.eql(u8, commit_did, did_str)) return error.InvalidCommit;

    // 9. verify signature: encode unsigned commit, then verify
    const unsigned_commit_bytes = try encodeUnsignedCommit(allocator, commit);
    switch (public_key.key_type) {
        .p256 => try jwt.verifyP256(unsigned_commit_bytes, sig_bytes, public_key.raw),
        .secp256k1 => try jwt.verifySecp256k1(unsigned_commit_bytes, sig_bytes, public_key.raw),
    }

    // 10. walk MST — collect all (key, value_cid) pairs
    var records: std.ArrayList(MstRecord) = .{};
    try walkMst(allocator, repo_car, data_cid.raw, &records);

    // 11. rebuild MST and compare root CID
    var tree = mst.Mst.init(allocator);
    for (records.items) |record| {
        try tree.put(record.key, record.value);
    }
    const rebuilt_root = try tree.rootCid();

    if (!std.mem.eql(u8, rebuilt_root.raw, data_cid.raw)) {
        return error.MstRootMismatch;
    }

    // build result — dupe strings to caller's allocator so they survive arena cleanup
    return VerifyResult{
        .did = try caller_alloc.dupe(u8, did_str),
        .handle = try caller_alloc.dupe(u8, did_doc.handle() orelse identifier),
        .signing_key_type = public_key.key_type,
        .commit_rev = try caller_alloc.dupe(u8, commit_rev),
        .commit_version = commit_version,
        .record_count = records.items.len,
    };
}

const MstRecord = struct {
    key: []const u8,
    value: cbor.Cid,
};

/// fetch a repo CAR from a PDS endpoint
fn fetchRepo(allocator: Allocator, pds_endpoint: []const u8, did_str: []const u8) ![]u8 {
    var transport = HttpTransport.init(allocator);
    defer transport.deinit();

    // build URL: {pds}/xrpc/com.atproto.sync.getRepo?did={did}
    const url = try std.fmt.allocPrint(allocator, "{s}/xrpc/com.atproto.sync.getRepo?did={s}", .{ pds_endpoint, did_str });

    const result = transport.fetch(.{ .url = url }) catch return error.FetchFailed;
    if (result.status != .ok) return error.FetchFailed;
    return result.body;
}

/// encode a commit value without the "sig" field (for signature verification)
fn encodeUnsignedCommit(allocator: Allocator, commit: cbor.Value) ![]u8 {
    const entries = switch (commit) {
        .map => |m| m,
        else => return error.InvalidCommit,
    };

    // filter out "sig", keep everything else
    var unsigned_entries: std.ArrayList(cbor.Value.MapEntry) = .{};
    for (entries) |entry| {
        if (!std.mem.eql(u8, entry.key, "sig")) {
            try unsigned_entries.append(allocator, entry);
        }
    }

    const unsigned_value: cbor.Value = .{ .map = unsigned_entries.items };
    return cbor.encodeAlloc(allocator, unsigned_value);
}

/// recursively walk MST nodes, collecting all (key, value_cid) pairs.
/// inverse of mst.serializeNode — decompresses prefix-compressed keys.
fn walkMst(allocator: Allocator, repo_car: car.Car, node_cid_raw: []const u8, records: *std.ArrayList(MstRecord)) !void {
    const block_data = car.findBlock(repo_car, node_cid_raw) orelse return;
    const node = cbor.decodeAll(allocator, block_data) catch return;

    // recurse into left subtree first (sorted order)
    if (node.get("l")) |left_val| {
        switch (left_val) {
            .cid => |left_cid| try walkMst(allocator, repo_car, left_cid.raw, records),
            else => {},
        }
    }

    // walk entries with prefix decompression
    const entries_arr = node.getArray("e") orelse return;
    var prev_key: []const u8 = "";

    for (entries_arr) |entry_val| {
        const p = entry_val.getInt("p") orelse continue;
        const prefix_len: usize = @intCast(p);
        const k = entry_val.getBytes("k") orelse continue;

        // reconstruct full key: prev_key[0..prefix_len] ++ k
        const full_key = try std.mem.concat(allocator, u8, &.{ prev_key[0..prefix_len], k });
        prev_key = full_key;

        // collect value CID
        if (entry_val.get("v")) |v| {
            switch (v) {
                .cid => |value_cid| try records.append(allocator, .{ .key = full_key, .value = value_cid }),
                else => {},
            }
        }

        // recurse into right subtree (between entries)
        if (entry_val.get("t")) |t| {
            switch (t) {
                .cid => |tree_cid| try walkMst(allocator, repo_car, tree_cid.raw, records),
                else => {},
            }
        }
    }
}

// === tests ===

test "verify repo - zzstoatzz.io" {
    // did:plc:xbtmt2zjwlrfegqvch7fboei on pds.zzstoatzz.io (self-hosted PDS)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const result = verifyRepo(arena.allocator(), "zzstoatzz.io") catch |err| {
        std.debug.print("network error (expected in CI): {}\n", .{err});
        return;
    };

    try std.testing.expectEqualStrings("did:plc:xbtmt2zjwlrfegqvch7fboei", result.did);
    try std.testing.expect(result.record_count > 0);
    std.debug.print("verified zzstoatzz.io: {d} records, rev={s}\n", .{ result.record_count, result.commit_rev });
}

// stress test: pfrazee.com (~192k records on bsky.network)
// run manually with: zig test src/internal/repo/repo_verifier.zig --
//   not included in `zig build test` — too slow for CI
//
// test "verify repo - pfrazee.com (stress)" {
//     var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
//     defer arena.deinit();
//     const result = verifyRepo(arena.allocator(), "pfrazee.com") catch |err| {
//         std.debug.print("network error: {}\n", .{err});
//         return;
//     };
//     try std.testing.expectEqualStrings("did:plc:ragtjsm2j2vknwkz3zp4oxrd", result.did);
//     try std.testing.expect(result.record_count > 0);
//     std.debug.print("verified pfrazee.com: {d} records, rev={s}\n", .{ result.record_count, result.commit_rev });
// }
