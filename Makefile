.PHONY: build run

build:
	cargo build --release
	echo "Copy files"
	cp contrib/settings.yaml target/release
	tar -cvf dist.tar.gz target/release/rbpf target/release/settings.yaml
	echo "Build done"

run:
	RUST_LOG=info cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- -c contrib/settings.yaml
