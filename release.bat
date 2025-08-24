cargo build --release
cargo build --release --target x86_64-pc-windows-msvc
git tag v1.0.0
git push origin v1.0.0