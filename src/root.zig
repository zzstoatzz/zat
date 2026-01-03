//! zat - zig atproto primitives (alpha)
//!
//! low-level building blocks for atproto applications.
//! not a full sdk - just the pieces everyone reimplements.
//!
//! ## stability
//!
//! this is alpha software (0.0.1-alpha). the public API is minimal by design.
//! new features start in `internal` and get promoted here when stable.
//!
//! ## public api
//!
//! currently empty - everything is still in internal while we iterate.
//!
//! ## internal api
//!
//! for bleeding-edge features, use the internal module directly:
//!
//! ```zig
//! const zat = @import("zat");
//!
//! // internal APIs - subject to change
//! const tid = zat.internal.Tid.parse("...") orelse return error.InvalidTid;
//! const uri = zat.internal.AtUri.parse("at://did:plc:xyz/collection/rkey") orelse return error.InvalidUri;
//! const did = zat.internal.Did.parse("did:plc:xyz") orelse return error.InvalidDid;
//! ```
//!
//! when these stabilize, they'll be promoted to `zat.Tid`, `zat.AtUri`, etc.

/// experimental and in-progress APIs.
/// everything here is subject to change without notice.
pub const internal = @import("internal.zig");

// --- stable public API ---
// (promoted from internal when ready)
//
// example of promotion:
// pub const Tid = internal.Tid;

test {
    _ = internal;
}
