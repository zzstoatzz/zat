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

# run firehose smoke test (CBOR/CAR/CID on live production data)
firehose-smoke:
    zig build firehose-smoke -Doptimize=ReleaseFast && ./zig-out/bin/firehose-smoke
