#!/bin/bash
set -ex

# Run tests in QEMU with a pre-built initramfs and a specific kernel.
#
# Usage: QEMU_ARCH=x86_64 ./run-qemu.sh <kernel-version> <initramfs-path>

KERNEL_VERSION="${1:?Usage: $0 <kernel-version> <initramfs-path>}"
INITRAMFS="${2:?Usage: $0 <kernel-version> <initramfs-path>}"
QEMU_ARCH="${QEMU_ARCH:-x86_64}"
KERN_DIR="${KERN_DIR:-ci-kernels}"

# Check inputs
if [[ ! -f "$INITRAMFS" ]]; then
    echo "ERROR: Initramfs not found at $INITRAMFS"
    exit 1
fi

if [[ ! -f "${KERN_DIR}/${KERNEL_VERSION}/vmlinuz" ]]; then
    echo "ERROR: Kernel ${KERNEL_VERSION} not found at ${KERN_DIR}/${KERNEL_VERSION}/vmlinuz"
    echo ""
    echo "To download kernel images:"
    echo "  QEMU_ARCH=$QEMU_ARCH ./download-kernel.sh $KERNEL_VERSION"
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
    -initrd "$INITRAMFS" \
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
