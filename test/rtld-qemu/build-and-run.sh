#!/bin/bash
set -ex

# Configuration
KERNEL_VERSION="${1:-5.10.217}"
QEMU_ARCH="${QEMU_ARCH:-x86_64}"
DISTRO="${DISTRO:-ubuntu}"  # debian or ubuntu
RELEASE="${RELEASE:-jammy}"  # jammy/noble for ubuntu (with USDT probes), bullseye for debian
ROOTFS_DIR="rootfs"
OUTPUT_DIR="output"
KERN_DIR="${KERN_DIR:-ci-kernels}"
CACHE_DIR="${CACHE_DIR:-/tmp/debootstrap-cache}"

echo "Building rootfs with $DISTRO $RELEASE..."

# Clean up previous builds
rm -rf "$ROOTFS_DIR" "$OUTPUT_DIR"
mkdir -p "$ROOTFS_DIR" "$OUTPUT_DIR" "$CACHE_DIR"

# Determine debootstrap architecture
DEBOOTSTRAP_ARCH="amd64"
case "$QEMU_ARCH" in
    x86_64)
        DEBOOTSTRAP_ARCH="amd64"
        ;;
    aarch64)
        DEBOOTSTRAP_ARCH="arm64"
        ;;
esac

# Choose mirror based on distro and architecture
if [[ "$DISTRO" == "ubuntu" ]]; then
    # Ubuntu ARM64 packages are on ports.ubuntu.com
    if [[ "$DEBOOTSTRAP_ARCH" == "arm64" ]]; then
        MIRROR="http://ports.ubuntu.com/ubuntu-ports/"
    else
        MIRROR="http://archive.ubuntu.com/ubuntu/"
    fi
else
    MIRROR="http://deb.debian.org/debian/"
fi

# Create minimal rootfs with debootstrap (requires sudo for chroot operations)
echo "Running debootstrap to create $DISTRO $RELEASE rootfs for $DEBOOTSTRAP_ARCH..."
sudo debootstrap --variant=minbase \
    --arch="$DEBOOTSTRAP_ARCH" \
    --cache-dir="$CACHE_DIR" \
    "$RELEASE" "$ROOTFS_DIR" "$MIRROR"

# Change ownership of rootfs to current user to avoid needing sudo for subsequent operations
sudo chown -R "$(id -u):$(id -g)" "$ROOTFS_DIR"

# Build the rtld test binary (must be dynamic for dlopen to work)
echo "Building rtld test binary for $DISTRO $RELEASE $DEBOOTSTRAP_ARCH..."

# Determine Go architecture
GOARCH="amd64"
case "$QEMU_ARCH" in
    x86_64)
        GOARCH="amd64"
        ;;
    aarch64)
        GOARCH="arm64"
        ;;
esac

# For cross-compilation or Ubuntu jammy/noble, local build works (host has compatible or newer glibc)
# For older distros, would need Docker build (disabled by default for speed)
if [[ "${USE_DOCKER}" == "1" ]] && command -v docker &> /dev/null; then
    # Determine base image
    if [[ "$DISTRO" == "ubuntu" ]]; then
        BASE_IMAGE="ubuntu:${RELEASE}"
    else
        BASE_IMAGE="debian:${RELEASE}"
    fi

    # Build in container to match target glibc (slow, downloads Go)
    echo "Using Docker to build with matching glibc version..."
    docker run --rm \
        -v "$(pwd)/../..:/workspace" \
        -w /workspace/test/rtld-qemu \
        --platform "linux/${DEBOOTSTRAP_ARCH}" \
        "$BASE_IMAGE" \
        bash -c "apt-get update -qq && apt-get install -y -qq wget libc6-dev gcc > /dev/null 2>&1 && \
                 wget -q https://go.dev/dl/go1.24.7.linux-${GOARCH}.tar.gz && \
                 tar -C /usr/local -xzf go1.24.7.linux-${GOARCH}.tar.gz && \
                 export PATH=/usr/local/go/bin:\$PATH && \
                 CGO_ENABLED=1 go test -c -o rtld.test ../../interpreter/rtld"
else
    # Local build with cross-compilation if needed
    echo "Building locally for ${GOARCH}..."
    CGO_ENABLED=1 GOARCH=${GOARCH} go test -c -o rtld.test \
        ../../interpreter/rtld
fi

# Copy test binary into rootfs
cp rtld.test "$ROOTFS_DIR/rtld.test"
chmod +x "$ROOTFS_DIR/rtld.test"

# List dynamic dependencies for debugging
echo "Test binary dependencies:"
ldd rtld.test || true

# Create init script
cat << 'EOF' > "$ROOTFS_DIR/init"
#!/bin/sh
echo "===== RTLD Test Environment ====="
echo "Kernel: $(uname -r)"
echo "Hostname: $(hostname)"

# Find and display ld.so info
LDSO=$(find /lib* /usr/lib* -name 'ld-linux*' -o -name 'ld-*.so*' 2>/dev/null | head -1)
echo "ld.so location: $LDSO"
if [ -n "$LDSO" ]; then
    echo "ld.so version: $($LDSO --version | head -1)"
fi

# Find libm for dlopen test
LIBM=$(find /lib* /usr/lib* -name 'libm.so*' 2>/dev/null | head -1)
echo "libm.so location: $LIBM"

echo "================================="

# Mount required filesystems
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sys /sys 2>/dev/null || true
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true

# Enable debug logging
export DEBUG_TEST=1

# Run the TestIntegrationSingleShot test specifically
echo ""
echo "Running RTLD TestIntegrationSingleShot test..."
timeout -s KILL 60 /rtld.test -test.v -test.run='TestIntegrationSingleShot' -test.timeout=30s
RESULT=$?

if [ $RESULT -eq 0 ]; then
    echo ""
    echo "===== TEST PASSED ====="
elif [ $RESULT -eq 137 ] || [ $RESULT -eq 124 ]; then
    echo ""
    echo "===== TEST TIMED OUT ====="
else
    echo ""
    echo "===== TEST FAILED (exit code: $RESULT) ====="
fi

# Give time to see output before shutdown
sleep 1

# Try to cleanly shutdown QEMU
# The sysrq 'o' trigger will power off the system
echo o > /proc/sysrq-trigger 2>/dev/null

# If sysrq doesn't work, force halt
sleep 1
poweroff -f 2>/dev/null || halt -f
EOF
chmod +x "$ROOTFS_DIR/init"

# Create initramfs
echo "Creating initramfs..."
(cd "$ROOTFS_DIR" && find . | cpio -o -H newc | gzip > "../$OUTPUT_DIR/initramfs.gz")

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
supportKVM=$(grep -E 'vmx|svm' /proc/cpuinfo || true)
if [ "$supportKVM" ] && [ "$QEMU_ARCH" = "$(uname -m)" ]; then
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

# Run QEMU
${sudo} qemu-system-${QEMU_ARCH} ${additionalQemuArgs} \
    -nographic \
    -monitor none \
    -serial mon:stdio \
    -m 2G \
    -kernel "${KERN_DIR}/${KERNEL_VERSION}/vmlinuz" \
    -initrd "$OUTPUT_DIR/initramfs.gz" \
    -append "${CONSOLE_ARG} init=/init quiet loglevel=3" \
    -no-reboot \
    -display none

EXIT_CODE=$?

# QEMU with sysrq poweroff returns 0 on clean shutdown
if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ Test completed successfully"
    exit 0
else
    echo "❌ Test failed with QEMU exit code $EXIT_CODE"
    exit $EXIT_CODE
fi