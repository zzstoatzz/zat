//! zat internal module
//!
//! experimental APIs that haven't stabilized yet.
//! everything here is subject to change without notice.
//!
//! when an API stabilizes, it gets promoted to root.zig.

pub const Tid = @import("internal/tid.zig").Tid;
pub const AtUri = @import("internal/at_uri.zig").AtUri;
pub const Did = @import("internal/did.zig").Did;

test {
    _ = @import("internal/tid.zig");
    _ = @import("internal/at_uri.zig");
    _ = @import("internal/did.zig");
}
