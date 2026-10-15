// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#define NOINLINE __attribute__((noinline))
#define INLINE static inline __attribute__((always_inline))

extern int puts(const char*);

INLINE void say(const char* s) {
  puts(s);
}

NOINLINE void one(void) {
  puts("one");
}

NOINLINE void two(void) {
  puts("two");
}

NOINLINE void pick(int c) {
  if (c) { say("a"); one(); } else { say("b"); two(); }
}

int main(int argc, char** argv) {
  (void)argv;
  for (int i = 0; i < argc; i++) pick(i & 1);
  return 0;
}
