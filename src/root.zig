//! zat - zig atproto primitives
//!
//! parsing and validation for AT Protocol string formats.

// identifiers
pub const Tid = @import("internal/tid.zig").Tid;
pub const Did = @import("internal/did.zig").Did;
pub const Handle = @import("internal/handle.zig").Handle;
pub const Nsid = @import("internal/nsid.zig").Nsid;
pub const Rkey = @import("internal/rkey.zig").Rkey;

// uris
pub const AtUri = @import("internal/at_uri.zig").AtUri;

test {
    _ = @import("internal/tid.zig");
    _ = @import("internal/did.zig");
    _ = @import("internal/handle.zig");
    _ = @import("internal/nsid.zig");
    _ = @import("internal/rkey.zig");
    _ = @import("internal/at_uri.zig");
}
