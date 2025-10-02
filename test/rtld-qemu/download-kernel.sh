#!/bin/bash
set -e

KERNEL_VERSION="${1:-5.10.217}"
KERN_DIR="${KERN_DIR:-ci-kernels}"

echo "Downloading kernel ${KERNEL_VERSION} from ghcr.io/cilium/ci-kernels..."

# Create directory
mkdir -p "${KERN_DIR}"

# Check if already exists
if [[ -f "${KERN_DIR}/${KERNEL_VERSION}/vmlinuz" ]]; then
    echo "Kernel ${KERNEL_VERSION} already exists at ${KERN_DIR}/${KERNEL_VERSION}/vmlinuz"
    exit 0
fi

# Pull and extract kernel from Docker image
echo "Pulling Docker image..."
docker pull "ghcr.io/cilium/ci-kernels:${KERNEL_VERSION}"

echo "Extracting kernel..."
# Use a unique container name to avoid conflicts
CONTAINER_NAME="kernel-extract-$$"
docker create --name "${CONTAINER_NAME}" "ghcr.io/cilium/ci-kernels:${KERNEL_VERSION}" /bin/true
docker cp "${CONTAINER_NAME}:/boot" "${KERN_DIR}/${KERNEL_VERSION}"
docker rm "${CONTAINER_NAME}"

if [[ -f "${KERN_DIR}/${KERNEL_VERSION}/vmlinuz" ]]; then
    echo "✅ Kernel ${KERNEL_VERSION} downloaded successfully"
    ls -la "${KERN_DIR}/${KERNEL_VERSION}/"
else
    echo "❌ Failed to download kernel"
    exit 1
fi