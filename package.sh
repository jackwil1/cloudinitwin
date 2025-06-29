cargo build --release
rm -rf package
mkdir -p package/cloudinitwin
cp target/release/cloudinitwin package/cloudinitwin/CloudInitWin.exe
cp scripts/* package/cloudinitwin/