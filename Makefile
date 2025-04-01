.PHONY: build run

build:
	cargo build --release
	echo "Copy files"
	cp -r contrib/rules target/release
	cp -r contrib/settings target/release
	tar -cvf dist.tar.gz target/release/rbpf_loader target/release/rbpf_http target/release/rules target/release/settings
	echo "Build done"

run-loader:
	RUST_LOG=info cargo run --release --bin rbpf_loader --config 'target."cfg(all())".runner="sudo -E"' -- -c contrib/settings/main.yaml -r contrib/rules/

run-http:
	RUST_LOG=info cargo run --release --bin rbpf_http -- -c contrib/settings/http.yaml
