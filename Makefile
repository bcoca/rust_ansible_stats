.PHONY: all clean build debug release

all: clean build

clean:
	cargo clean

build:
	RUSTFLAGS="--remap-path-prefix ${HOME}=~" cargo build

debug:
	RUSTFLAGS="--remap-path-prefix ${HOME}=~" cargo build --profile=release-with-debug

release:
	cargo build --release
