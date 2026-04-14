#!/bin/bash
set -e

case "$(uname -m)" in
    x86_64)  _default_arch="x86_64" ;;
    aarch64) _default_arch="aarch64" ;;
    *)       _default_arch="x86_64" ;;
esac
QEMU_ARCH="${QEMU_ARCH:-$_default_arch}"
PARCAGPU_DIR="${PARCAGPU_DIR:-parcagpu-lib}"

# Map QEMU arch to Docker platform
case "$QEMU_ARCH" in
    x86_64)
        DOCKER_PLATFORM="linux/amd64"
        ;;
    aarch64)
        DOCKER_PLATFORM="linux/arm64"
        ;;
    *)
        echo "Unsupported architecture: $QEMU_ARCH"
        exit 1
        ;;
esac

# Create directory
mkdir -p "${PARCAGPU_DIR}"

# Download libparcagpucupti.so if not already present.
if [[ ! -f "${PARCAGPU_DIR}/libparcagpucupti.so" ]]; then
    echo "Downloading libparcagpucupti.so for ${QEMU_ARCH} from ghcr.io/parca-dev/parcagpu:latest..."

    # Pull and extract .so from Docker image using buildx (supports multi-arch)
    echo "Pulling Docker image for ${DOCKER_PLATFORM}..."
    TMPDIR=$(mktemp -d)
    echo "FROM ghcr.io/parca-dev/parcagpu:latest" \
      | docker buildx build --platform "${DOCKER_PLATFORM}" \
        --quiet --pull --output="${TMPDIR}" -

    # Find and copy the .so (may be versioned, e.g. libparcagpucupti.so.13)
    SOFILE=$(find "${TMPDIR}" -name 'libparcagpucupti.so*' -type f | sort -V | tail -1)
    if [[ -n "${SOFILE}" ]]; then
        cp "${SOFILE}" "${PARCAGPU_DIR}/libparcagpucupti.so"
    else
        echo "❌ libparcagpucupti.so not found in container image"
        rm -rf "${TMPDIR}"
        exit 1
    fi

    rm -rf "${TMPDIR}"

    if [[ ! -f "${PARCAGPU_DIR}/libparcagpucupti.so" ]]; then
        echo "❌ Failed to download libparcagpucupti.so"
        exit 1
    fi

    echo "✅ libparcagpucupti.so downloaded successfully"
    ls -la "${PARCAGPU_DIR}/libparcagpucupti.so"
fi

# Build mock libcupti.so and libcuda.so from the parcagpu repo's test sources.
# These provide real mock implementations of all CUPTI/CUDA APIs that
# libparcagpucupti.so resolves via dlsym at runtime.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MOCK_HEADERS="${SCRIPT_DIR}/mock-cupti-headers"
PARCAGPU_REPO="parca-dev/parcagpu"

# Determine compiler for the target arch.
if [ "$QEMU_ARCH" = "aarch64" ] && [ "$(uname -m)" != "aarch64" ]; then
    STUB_CC="${CC:-aarch64-linux-gnu-gcc}"
else
    STUB_CC="${CC:-cc}"
fi

if [[ ! -f "${PARCAGPU_DIR}/libcupti.so" ]]; then
    echo "Building mock libcupti.so from ${PARCAGPU_REPO}..."
    MOCK_SRC=$(mktemp -d)

    # Download mock sources from the parcagpu repo.
    for f in test/mock_cupti.c test/mock_cuda.c; do
        curl -sL "https://raw.githubusercontent.com/${PARCAGPU_REPO}/main/${f}" \
            -o "${MOCK_SRC}/$(basename "$f")"
    done

    # Build mock libcupti.so with our minimal type-definition headers.
    ${STUB_CC} -shared -fPIC -o "${PARCAGPU_DIR}/libcupti.so" \
        -Wl,-soname,"libcupti.so" \
        -I"${MOCK_HEADERS}" \
        "${MOCK_SRC}/mock_cupti.c"
    echo "✅ Built mock libcupti.so"

    # Build mock libcuda.so.
    ${STUB_CC} -shared -fPIC -o "${PARCAGPU_DIR}/libcuda.so" \
        -Wl,-soname,"libcuda.so.1" \
        -I"${MOCK_HEADERS}" \
        "${MOCK_SRC}/mock_cuda.c"
    # Triton's Proton looks for the versioned soname.
    ln -sf libcuda.so "${PARCAGPU_DIR}/libcuda.so.1"
    echo "✅ Built mock libcuda.so"

    rm -rf "${MOCK_SRC}"
fi
