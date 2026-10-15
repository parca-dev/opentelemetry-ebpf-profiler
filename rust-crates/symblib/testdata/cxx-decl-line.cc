// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#define NOINLINE __attribute__((noinline))
#define INLINE __attribute__((always_inline)) inline

extern "C" int puts(const char*);

struct S {
  NOINLINE void defined_in_class() {
    puts("defined_in_class");
  }

  NOINLINE void defined_out_of_class();

  INLINE void inlined();
};

NOINLINE void S::defined_out_of_class() {
  puts("defined_out_of_class");
}

INLINE void S::inlined() {
  puts("inlined");
}

int main() {
  S s;
  s.defined_in_class();
  s.defined_out_of_class();
  s.inlined();
}
