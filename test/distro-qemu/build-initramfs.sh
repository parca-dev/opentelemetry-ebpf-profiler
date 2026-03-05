#!/bin/bash
set -ex

# Build an initramfs containing test binaries, shared libraries, and busybox.
# The resulting initramfs is arch-specific but kernel-independent.
# Must be run on the same architecture as the target (no cross-compilation).
#
# Usage: QEMU_ARCH=x86_64 ./build-initramfs.sh [output-path]

QEMU_ARCH="${QEMU_ARCH:-$(uname -m)}"
OUTPUT="${1:-initramfs.gz}"
# Make output path absolute (cpio runs in a subshell with different cwd)
[[ "$OUTPUT" != /* ]] && OUTPUT="$(pwd)/$OUTPUT"
PARCAGPU_DIR="${PARCAGPU_DIR:-parcagpu-lib}"

ROOTFS_DIR=$(mktemp -d /tmp/distro-qemu-rootfs.XXXXXX)
BUILD_DIR=$(mktemp -d /tmp/distro-qemu-build.XXXXXX)

cleanup() {
    rm -rf "$ROOTFS_DIR" "$BUILD_DIR"
}
trap cleanup EXIT

timer_start() { TIMER_START=$(date +%s); }
timer_end() { echo "::> $1 took $(( $(date +%s) - TIMER_START ))s"; }

# Determine architecture
case "$QEMU_ARCH" in
    x86_64)  GOARCH="amd64";;
    aarch64) GOARCH="arm64";;
    *) echo "Unsupported QEMU_ARCH: $QEMU_ARCH"; exit 1;;
esac

# Download parcagpu library
timer_start
PARCAGPU_DIR="${PARCAGPU_DIR}" ./download-parcagpu.sh
timer_end "download parcagpu"

# Build test binaries (must be dynamic for dlopen to work)
timer_start
echo "Building test binaries for $GOARCH..."
REPO_ROOT="$(cd ../.. && pwd)"
TEST_PKGS="./interpreter/rtld ./support/usdt/test ./test/cudaverify"
(
    cd "${REPO_ROOT}"
    CGO_ENABLED=1 GOARCH=${GOARCH} \
        go test -c -o "${BUILD_DIR}/" ${TEST_PKGS}
)
timer_end "go test -c (build test binaries)"

# Create minimal rootfs (busybox + shared libs only)
timer_start
echo "Creating minimal rootfs..."
mkdir -p "$ROOTFS_DIR"/{bin,proc,sys,dev,tmp}

# Install busybox for shell and basic utilities
BUSYBOX=$(command -v busybox 2>/dev/null || true)
if [ -z "$BUSYBOX" ]; then
    echo "ERROR: busybox not found. Install busybox-static."
    exit 1
fi
cp "$BUSYBOX" "$ROOTFS_DIR/bin/busybox"
chmod +x "$ROOTFS_DIR/bin/busybox"
for cmd in sh mount umount dmesg poweroff halt reboot hostname uname find head tail sleep cat grep; do
    ln -sf busybox "$ROOTFS_DIR/bin/$cmd"
done

# Copy shared libraries needed by test binaries using ldd
copy_lib_deps() {
    local binary="$1"
    # Copy ELF interpreter
    local interp
    interp=$(readelf -l "$binary" 2>/dev/null | grep -oP 'Requesting program interpreter: \K[^\]]+' || true)
    if [ -n "$interp" ] && [ -f "$interp" ]; then
        install -Dm755 "$interp" "$ROOTFS_DIR$interp"
    fi
    # Copy all shared library dependencies
    ldd "$binary" 2>/dev/null | while read -r line; do
        lib=$(echo "$line" | grep -oP '=> \K/\S+' || true)
        if [ -n "$lib" ] && [ -f "$lib" ] && [ ! -f "$ROOTFS_DIR$lib" ]; then
            real=$(readlink -f "$lib")
            install -Dm755 "$real" "$ROOTFS_DIR$real"
            if [ "$real" != "$lib" ]; then
                mkdir -p "$ROOTFS_DIR$(dirname "$lib")"
                ln -sf "$real" "$ROOTFS_DIR$lib"
            fi
        fi
    done
}

for binary in "${BUILD_DIR}"/*.test; do
    copy_lib_deps "$binary"
done

# Ensure libm.so is available for rtld test (it dlopens libm at runtime,
# so it won't appear in ldd output)
LIBM=$(find /lib* /usr/lib* -name 'libm.so.6' -type f 2>/dev/null | head -1)
if [ -n "$LIBM" ] && [ ! -f "$ROOTFS_DIR$LIBM" ]; then
    real=$(readlink -f "$LIBM")
    install -Dm755 "$real" "$ROOTFS_DIR$real"
    if [ "$real" != "$LIBM" ]; then
        mkdir -p "$ROOTFS_DIR$(dirname "$LIBM")"
        ln -sf "$real" "$ROOTFS_DIR$LIBM"
    fi
fi

# Copy test binaries and parcagpu .so into rootfs
cp "${BUILD_DIR}"/*.test "$ROOTFS_DIR/"
cp "${PARCAGPU_DIR}/libparcagpucupti.so" "$ROOTFS_DIR/"
copy_lib_deps "${PARCAGPU_DIR}/libparcagpucupti.so"

# Copy stub libcupti .so into the RUNPATH (/usr/local/cuda/lib64) so the
# dynamic linker resolves the DT_NEEDED entry without a real CUDA install.
mkdir -p "$ROOTFS_DIR/usr/local/cuda/lib64"
for stub in "${PARCAGPU_DIR}"/libcupti.so*; do
    [ -f "$stub" ] && cp "$stub" "$ROOTFS_DIR/usr/local/cuda/lib64/"
done

# Show what we have for debugging
echo "Test binary dependencies:"
ldd "${BUILD_DIR}/rtld.test" || true
echo ""
echo "Rootfs contents:"
find "$ROOTFS_DIR" -type f -o -type l | sort
echo ""

# Create init script
cat << 'INIT_EOF' > "$ROOTFS_DIR/init"
#!/bin/sh
export PATH=/bin

echo "===== Test Environment ====="
echo "Kernel: $(uname -r)"

# Mount required filesystems
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sys /sys 2>/dev/null || true
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true

# Run the tests
echo ""
RESULT=0
for test_bin in /rtld.test /test.test "/cudaverify.test -so-path=/libparcagpucupti.so"; do
    name=$(echo "$test_bin" | cut -d' ' -f1)
    T0=$(cat /proc/uptime | cut -d' ' -f1)
    $test_bin -test.v
    rc=$?
    T1=$(cat /proc/uptime | cut -d' ' -f1)
    echo "::> $name took ${T0}s-${T1}s (uptime)"
    if [ $rc -ne 0 ]; then
        RESULT=$rc
        break
    fi
done

if [ $RESULT -eq 0 ]; then
    echo ""
    echo "===== TEST PASSED ====="
elif [ $RESULT -eq 137 ] || [ $RESULT -eq 124 ]; then
    echo ""
    echo "===== TEST TIMED OUT ====="
else
    echo ""
    echo "===== BPF dmesg ====="
    dmesg | tail -60
    echo "===== TEST FAILED (exit code: $RESULT) ====="
fi

# Shutdown
sleep 1
echo o > /proc/sysrq-trigger 2>/dev/null
sleep 1
poweroff -f 2>/dev/null || halt -f
INIT_EOF
chmod +x "$ROOTFS_DIR/init"
timer_end "create rootfs"

# Create initramfs
timer_start
echo "Creating initramfs..."
(cd "$ROOTFS_DIR" && find . | cpio -o -H newc | gzip > "$OUTPUT")
echo "Initramfs created: $OUTPUT ($(du -h "$OUTPUT" | cut -f1))"
timer_end "create initramfs"
