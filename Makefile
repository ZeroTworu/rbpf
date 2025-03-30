.PHONY: build run

build:
	cargo build --release
	echo "Copy files"
	cp -r contrib/rules target/release
	cp contrib/settings.yaml target/release/settings.yaml
	tar -cvf dist.tar.gz target/release/rbpf target/release/rules target/release/settings.yaml
	echo "Build done"

run:
	RUST_LOG=info cargo run --release --config 'target."cfg(all())".runner="sudo -E"' -- -c contrib/settings.yaml -r contrib/rules/
