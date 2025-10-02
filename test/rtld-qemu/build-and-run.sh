#!/bin/bash
set -ex

# Configuration
KERNEL_VERSION="${1:-5.10.217}"
DISTRO="${DISTRO:-ubuntu}"  # debian or ubuntu
RELEASE="${RELEASE:-jammy}"  # jammy/noble for ubuntu (with USDT probes), bullseye for debian
ROOTFS_DIR="rootfs"
OUTPUT_DIR="output"
KERN_DIR="${KERN_DIR:-ci-kernels}"
CACHE_DIR="${CACHE_DIR:-/tmp/debootstrap-cache}"

echo "Building rootfs with $DISTRO $RELEASE..."

# Clean up previous builds
sudo rm -rf "$ROOTFS_DIR" "$OUTPUT_DIR"
mkdir -p "$ROOTFS_DIR" "$OUTPUT_DIR" "$CACHE_DIR"

# Choose mirror based on distro
if [[ "$DISTRO" == "ubuntu" ]]; then
    MIRROR="http://archive.ubuntu.com/ubuntu/"
else
    MIRROR="http://deb.debian.org/debian/"
fi

# Create minimal rootfs with debootstrap
echo "Running debootstrap to create $DISTRO $RELEASE rootfs..."
sudo debootstrap --variant=minbase \
    --cache-dir="$CACHE_DIR" \
    "$RELEASE" "$ROOTFS_DIR" "$MIRROR"

# Build the rtld test binary (must be dynamic for dlopen to work)
echo "Building rtld test binary for $DISTRO $RELEASE..."

# For Ubuntu jammy/noble, local build works (host has compatible or newer glibc)
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
        "$BASE_IMAGE" \
        bash -c "apt-get update -qq && apt-get install -y -qq wget libc6-dev gcc > /dev/null 2>&1 && \
                 wget -q https://go.dev/dl/go1.24.7.linux-amd64.tar.gz && \
                 tar -C /usr/local -xzf go1.24.7.linux-amd64.tar.gz && \
                 export PATH=/usr/local/go/bin:\$PATH && \
                 CGO_ENABLED=1 go test -c -o rtld.test ../../interpreter/rtld"
else
    # Local build (fast, works for Ubuntu jammy/noble and newer)
    echo "Building locally (works with Ubuntu jammy/noble and similar glibc versions)..."
    CGO_ENABLED=1 go test -c -o rtld.test \
        ../../interpreter/rtld
fi

# Copy test binary into rootfs
sudo cp rtld.test "$ROOTFS_DIR/rtld.test"
sudo chmod +x "$ROOTFS_DIR/rtld.test"

# List dynamic dependencies for debugging
echo "Test binary dependencies:"
ldd rtld.test || true

# Create init script
cat << 'EOF' | sudo tee "$ROOTFS_DIR/init" > /dev/null
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

# Halt the system using reboot -f (more reliable in minimal environments)
echo o > /proc/sysrq-trigger 2>/dev/null || reboot -f || halt -f
exit $RESULT
EOF
sudo chmod +x "$ROOTFS_DIR/init"

# Create initramfs
echo "Creating initramfs..."
(cd "$ROOTFS_DIR" && sudo find . | sudo cpio -o -H newc | gzip > "../$OUTPUT_DIR/initramfs.gz")

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

# Determine KVM support
QEMU_ACCEL=""
if [[ -r /dev/kvm && -w /dev/kvm ]] && grep -qE 'vmx|svm' /proc/cpuinfo; then
    QEMU_ACCEL="-enable-kvm"
    echo "Using KVM acceleration"
else
    echo "Running without KVM (slower)"
    SUDO_CMD="sudo"
fi

echo ""
echo "===== Starting QEMU with kernel ${KERNEL_VERSION} ====="
echo ""

# Run QEMU
${SUDO_CMD} qemu-system-x86_64 \
    ${QEMU_ACCEL} \
    -cpu host \
    -m 2G \
    -kernel "${KERN_DIR}/${KERNEL_VERSION}/vmlinuz" \
    -initrd "$OUTPUT_DIR/initramfs.gz" \
    -append "console=ttyS0 init=/init quiet loglevel=3" \
    -serial mon:stdio \
    -nographic \
    -no-reboot \
    -display none

EXIT_CODE=$?
if [ $EXIT_CODE -eq 0 ]; then
    echo "✅ Test completed successfully"
else
    echo "❌ Test failed with exit code $EXIT_CODE"
    exit $EXIT_CODE
fi