#!/bin/bash
ASAN_OPTIONS=detect_leaks=1 LSAN_OPTIONS=suppressions=${PWD}/cpp/lsan.supp MallocNanoZone='0' bazel run -c dbg  --config=asan //cpp/main:floe_test && \
ASAN_OPTIONS=detect_leaks=1 LSAN_OPTIONS=suppressions=${PWD}/cpp/lsan.supp MallocNanoZone='0' bazel run -c dbg  --config=asan //cpp/main:kat_test && \
ASAN_OPTIONS=detect_leaks=1 LSAN_OPTIONS=suppressions=${PWD}/cpp/lsan.supp MallocNanoZone='0' bazel run -c dbg  --config=asan //cpp/main:bounce_test
