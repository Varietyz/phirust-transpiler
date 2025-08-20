cargo build --release
cargo build --release --target x86_64-pc-windows-msvc
phi --phirust-remove
copy target\release\phirust-transpiler.exe "C:\Users\JayBa\.phicode\bin\"