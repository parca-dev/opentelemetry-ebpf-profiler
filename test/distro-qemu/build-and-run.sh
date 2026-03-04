#!/bin/bash
set -ex

# Configuration
KERNEL_VERSION="${1:-5.10.217}"
QEMU_ARCH="${QEMU_ARCH:-x86_64}"
ROOTFS_DIR=$(mktemp -d /tmp/distro-qemu-rootfs.XXXXXX)
OUTPUT_DIR=$(mktemp -d /tmp/distro-qemu-output.XXXXXX)
KERN_DIR="${KERN_DIR:-ci-kernels}"
PARCAGPU_DIR="${PARCAGPU_DIR:-parcagpu-lib}"

cleanup() {
    rm -rf "$ROOTFS_DIR" "$OUTPUT_DIR"
}
trap cleanup EXIT

# Download parcagpu library
PARCAGPU_DIR="${PARCAGPU_DIR}" ./download-parcagpu.sh

# Determine architecture
case "$QEMU_ARCH" in
    x86_64)  GOARCH="amd64";;
    aarch64) GOARCH="arm64";;
    *) echo "Unsupported QEMU_ARCH: $QEMU_ARCH"; exit 1;;
esac

# Build test binaries (must be dynamic for dlopen to work)
echo "Building test binaries for $GOARCH..."
REPO_ROOT="$(cd ../.. && pwd)"
TEST_PKGS="./interpreter/rtld ./support/usdt/test ./test/cudaverify"
(
    cd "${REPO_ROOT}"
    if [ "$GOARCH" = "arm64" ] && [ "$(uname -m)" = "x86_64" ]; then
        CGO_ENABLED=1 GOARCH=${GOARCH} CC=aarch64-linux-gnu-gcc \
            go test -c -o "${OUTPUT_DIR}/" ${TEST_PKGS}
    else
        CGO_ENABLED=1 GOARCH=${GOARCH} \
            go test -c -o "${OUTPUT_DIR}/" ${TEST_PKGS}
    fi
)

# Create minimal rootfs (busybox + shared libs only, no debootstrap)
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

# Copy shared libraries needed by test binaries
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
        # Match lines like: libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x...)
        lib=$(echo "$line" | grep -oP '=> \K/\S+' || true)
        if [ -n "$lib" ] && [ -f "$lib" ] && [ ! -f "$ROOTFS_DIR$lib" ]; then
            real=$(readlink -f "$lib")
            install -Dm755 "$real" "$ROOTFS_DIR$real"
            # Preserve symlink if the path differs from the real file
            if [ "$real" != "$lib" ]; then
                mkdir -p "$ROOTFS_DIR$(dirname "$lib")"
                ln -sf "$real" "$ROOTFS_DIR$lib"
            fi
        fi
    done
}

for binary in "${OUTPUT_DIR}"/*.test; do
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
cp "${OUTPUT_DIR}"/*.test "$ROOTFS_DIR/"
cp "${PARCAGPU_DIR}/libparcagpucupti.so" "$ROOTFS_DIR/"

# Show what we have for debugging
echo "Test binary dependencies:"
ldd "${OUTPUT_DIR}/rtld.test" || true
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
/rtld.test -test.v && /test.test -test.v && /cudaverify.test -test.v -so-path=/libparcagpucupti.so
RESULT=$?

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

# Create initramfs
echo "Creating initramfs..."
(cd "$ROOTFS_DIR" && find . | cpio -o -H newc | gzip > "$OUTPUT_DIR/initramfs.gz")

echo "Rootfs created: $OUTPUT_DIR/initramfs.gz ($(du -h $OUTPUT_DIR/initramfs.gz | cut -f1))"

# Check if kernel exists
if [[ ! -f "${KERN_DIR}/${KERNEL_VERSION}/vmlinuz" ]]; then
    echo ""
    echo "ERROR: Kernel ${KERNEL_VERSION} not found at ${KERN_DIR}/${KERNEL_VERSION}/vmlinuz"
    echo ""
    echo "To download kernel images:"
    echo "  mkdir -p ci-kernels"
    echo "  docker pull ghcr.io/cilium/ci-kernels:${KERNEL_VERSION}"
    echo "  docker create --name kernel-extract ghcr.io/cilium/ci-kernels:${KERNEL_VERSION}"
    echo "  docker cp kernel-extract:/boot ci-kernels/${KERNEL_VERSION}"
    echo "  docker rm kernel-extract"
    echo ""
    exit 1
fi

# Use sudo if /dev/kvm isn't accessible by the current user
sudo=""
if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  sudo="sudo"
fi

# Determine additional QEMU args based on architecture
additionalQemuArgs=""
if [ -e /dev/kvm ] && [ "$QEMU_ARCH" = "$(uname -m)" ]; then
  additionalQemuArgs="-enable-kvm"
fi

case "$QEMU_ARCH" in
    x86_64)
        CONSOLE_ARG="console=ttyS0"
        ;;
    aarch64)
        additionalQemuArgs+=" -machine virt -cpu max"
        CONSOLE_ARG="console=ttyAMA0"
        ;;
esac

echo ""
echo "===== Starting QEMU with kernel ${KERNEL_VERSION} on ${QEMU_ARCH} ====="
echo ""

# Run QEMU and capture output
QEMU_OUTPUT=$(mktemp)
${sudo} qemu-system-${QEMU_ARCH} ${additionalQemuArgs} \
    -nographic \
    -monitor none \
    -serial mon:stdio \
    -m 2G \
    -kernel "${KERN_DIR}/${KERNEL_VERSION}/vmlinuz" \
    -initrd "$OUTPUT_DIR/initramfs.gz" \
    -append "${CONSOLE_ARG} init=/init quiet loglevel=3" \
    -no-reboot \
    -display none \
    | tee "$QEMU_OUTPUT"

# Parse output for test result
if grep -q "===== TEST PASSED =====" "$QEMU_OUTPUT"; then
    rm -f "$QEMU_OUTPUT"
    echo ""
    echo "Test completed successfully"
    exit 0
elif grep -q "===== TEST FAILED" "$QEMU_OUTPUT"; then
    rm -f "$QEMU_OUTPUT"
    echo ""
    echo "Test failed"
    exit 1
elif grep -q "===== TEST TIMED OUT =====" "$QEMU_OUTPUT"; then
    rm -f "$QEMU_OUTPUT"
    echo ""
    echo "Test timed out"
    exit 124
else
    rm -f "$QEMU_OUTPUT"
    echo ""
    echo "Could not determine test result (QEMU may have crashed)"
    exit 2
fi
