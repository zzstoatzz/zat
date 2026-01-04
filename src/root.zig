//! zat - zig atproto primitives
//!
//! parsing and validation for AT Protocol string formats.
//! DID resolution for did:plc and did:web.

// string primitives
pub const Tid = @import("internal/tid.zig").Tid;
pub const Did = @import("internal/did.zig").Did;
pub const Handle = @import("internal/handle.zig").Handle;
pub const Nsid = @import("internal/nsid.zig").Nsid;
pub const Rkey = @import("internal/rkey.zig").Rkey;
pub const AtUri = @import("internal/at_uri.zig").AtUri;

// did resolution
pub const DidDocument = @import("internal/did_document.zig").DidDocument;
pub const DidResolver = @import("internal/did_resolver.zig").DidResolver;
pub const HandleResolver = @import("internal/handle_resolver.zig").HandleResolver;

// xrpc
pub const XrpcClient = @import("internal/xrpc.zig").XrpcClient;

// json helpers
pub const json = @import("internal/json.zig");

// service auth
pub const Jwt = @import("internal/jwt.zig").Jwt;
pub const multibase = @import("internal/multibase.zig");
pub const multicodec = @import("internal/multicodec.zig");
