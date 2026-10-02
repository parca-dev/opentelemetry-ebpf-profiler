# Distro QEMU Testing

This directory contains scripts to test USDT probe attachment and CUDA (parcagpu) probe discovery on different kernel versions using QEMU.

## Prerequisites

1. **Install required packages:**
   ```bash
   # For Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install -y qemu-system-x86 debootstrap
   ```

2. **Download a kernel image:**
   ```bash
   # Download kernel 5.10 (pre-6.6, will use single-shot mode)
   ./download-kernel.sh 5.10.217

   # Or download kernel 6.8 (post-6.6, supports multi-uprobe)
   ./download-kernel.sh 6.8.10
   ```

## Running Tests

### Quick Test (All-in-one)
```bash
# Test with kernel 5.10 (tests fallback/single-shot mode)
./build-and-run.sh 5.10.217

# Test with kernel 6.8 (tests multi-uprobe mode)
./build-and-run.sh 6.8.10
```

### Test Different Distributions
```bash
# Test with Ubuntu 24.04 (noble) - recommended, has USDT probes
DISTRO=ubuntu RELEASE=noble ./build-and-run.sh 5.10.217

# Test with Ubuntu 22.04 (jammy) - has USDT probes
DISTRO=ubuntu RELEASE=jammy ./build-and-run.sh 5.10.217

# Test with Ubuntu 20.04 (focal) - no USDT probes, uses fallback
DISTRO=ubuntu RELEASE=focal ./build-and-run.sh 5.10.217

# Test with Debian 11 (bullseye) - default, no USDT probes
DISTRO=debian RELEASE=bullseye ./build-and-run.sh 5.10.217
```

## What These Tests Do

1. **Builds a minimal initramfs** with busybox, the compiled test binaries and
   their shared library dependencies, and the parcagpu library with a stub libcupti.

2. **Boots QEMU** with:
   - Selected kernel version
   - Minimal initramfs containing our test environment
   - Serial console output

3. **Runs the tests**:
   - `support/usdt/test` - USDT probe attachment and argument decoding, in
     single-shot and multi-uprobe mode
   - `test/cudaverify` - end-to-end CUDA probe flow: libparcagpucupti.so is
     dlopen'ed after the process was first synchronized and must be discovered
     through MMAP events, then simulated kernel launches must produce timing events

## Expected Behavior

- **Kernel < 5.15**: Tests that need `bpf_get_attach_cookie` are skipped
- **Kernel < 6.6**: Single-shot mode only; multi-uprobe tests are skipped
- **Kernel >= 6.6**: Both single-shot and multi-uprobe modes are tested
- All tests that are not skipped should pass

## Available Kernels

Check available kernels at: https://github.com/cilium/ci-kernels/pkgs/container/ci-kernels/versions

Common versions to test:
- 5.4.276 (Ubuntu 20.04 LTS)
- 5.10.217 (Debian 11)
- 5.15.159 (Ubuntu 22.04 LTS)
- 6.1.91 (Debian 12)
- 6.6.31 (First with multi-uprobe support)
- 6.8.10 (Recent stable)

## Troubleshooting

1. **No KVM access**: The scripts will automatically use sudo if needed
2. **Slow without KVM**: Without KVM acceleration, tests run slower but still work
3. **Kernel not found**: Use `./download-kernel.sh <version>` to download
4. **debootstrap fails**: Make sure you have internet access for package downloads