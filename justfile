# zat

# show available commands
default:
    @just --list

# format code
fmt:
    zig fmt .

# check formatting (CI)
check:
    zig fmt --check .

# run tests
test:
    zig build test --summary all -freference-trace

# run CBOR codec benchmarks
bench:
    zig build bench -Doptimize=ReleaseFast
