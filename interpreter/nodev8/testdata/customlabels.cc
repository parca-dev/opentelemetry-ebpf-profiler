// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

struct napi_node_version {
  unsigned major, minor, patch;
  const char *release;
};

extern "C" __attribute__((visibility("default")))
int napi_get_node_version(void *env, const napi_node_version **result) {
  if (!env || !result) {
    return 1;
  }
  static const napi_node_version version = {22, 23, 4, "node"};
  *result = &version;
  return 0;
}

namespace v8 {
namespace internal {
// Hidden even in .dynsym: this exercises the exported accessor fallback.
thread_local void *g_current_isolate_;
}
class Isolate {
public:
  __attribute__((visibility("default"))) static void *TryGetCurrent();
};
void *Isolate::TryGetCurrent() { return internal::g_current_isolate_; }
}

int main() { return 0; }
