cmake_minimum_required(VERSION 3.25)
project(claybin LANGUAGES CXX VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# claybin is built on std::expected -- Result<T> and Status are aliases for it,
# and every fallible operation returns one. a toolchain without it fails with a
# few hundred lines of "no template named 'Result'", which says nothing useful.
#
# this check exists because CI hit exactly that: Ubuntu's default clang pairs
# with a libstdc++ too old for <expected>, and the build failed deep in
# bpf/emit.cpp rather than at configure time with a sentence anyone could act
# on. -std=c++23 alone does not imply the LIBRARY has it.
include(CheckCXXSourceCompiles)
set(CMAKE_REQUIRED_FLAGS "-std=c++23")
check_cxx_source_compiles("
  #include <expected>
  int main() { std::expected<int, char> e{1}; return e.has_value() ? 0 : 1; }
" CLAYBIN_HAS_EXPECTED)
unset(CMAKE_REQUIRED_FLAGS)
if(NOT CLAYBIN_HAS_EXPECTED)
  message(FATAL_ERROR
    "this compiler's standard library has no working <expected>.\n"
    "claybin needs it: Result<T> and Status are aliases for std::expected.\n"
    "known-good: gcc 13+, or clang 17+ built against libstdc++ 13+ or libc++ 16+.\n"
    "with clang on a distro whose default libstdc++ is older, either install a\n"
    "newer libstdc++ or add -stdlib=libc++ to CMAKE_CXX_FLAGS.")
endif()

option(CLAYBIN_TESTS "build tests" ON)

add_library(claybin STATIC
  src/bpf/emit.cpp
  src/plan/compile.cpp
  src/windows/compile.cpp
  src/macos/compile.cpp
  # These two are NOT linux-only despite their paths: each already ends in an
  # `#else` branch of portable stubs (cgroup::probe() reporting "linux-only",
  # probe_host() returning none()). Those branches had never been COMPILED,
  # because the files sat in the Linux-only list while src/plan/compile.cpp --
  # which calls cgroup::probe() and Group::release() -- is unconditional. So
  # every non-linux build of the library linked with undefined symbols, which
  # only stayed hidden while nothing off linux linked a test against it.
  src/plan/probe.cpp
  src/linux/cgroup.cpp
)
# POSIX-only implementations.
#
# These are not "linux-flavoured but portable" the way compile.cpp is -- they
# call open/read/close/readlink/getuid directly and have no Windows analogue,
# so there is nothing to shim. They were in the unconditional list, which only
# worked because compile.cpp sorts first and failed the MinGW build before the
# linker reached them.
#
# Grouped with the linux/ sources rather than given their own guard: the
# question "does this file need a POSIX host" has one answer and should have
# one list.
# Android reports CMAKE_SYSTEM_NAME "Android" but runs the same kernel API.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" OR CMAKE_SYSTEM_NAME STREQUAL "Android")
  target_sources(claybin PRIVATE
    src/broker/notify.cpp
    src/core/fd.cpp
    src/linux/apply.cpp
    src/linux/spawn.cpp)
endif()

# The macOS apply path. Same split as linux: macos/compile.cpp is pure and
# builds everywhere (its tests run in CI on a linux runner), while this file
# calls sandbox_init/fork/setrlimit and only exists on a mac.
#
# src/core/fd.cpp is POSIX, not linux: the macOS spawn path needs OwnedFd too,
# and leaving it in the linux-only list meant the Apple build linked without
# it and failed on OwnedFd::reset.
if(APPLE)
  target_sources(claybin PRIVATE
    src/core/fd.cpp
    src/macos/spawn.cpp)
endif()

# The Windows apply path. Same split as linux/macos: compile.cpp is pure and
# builds everywhere (its tests run in CI on a linux runner), spawn.cpp calls
# the AppContainer/Job/CreateProcess APIs and only exists on windows.
# Conditional rather than unconditional so the MSVC/MinGW library link keeps
# working for agentty's settings pane (which compiles plans on windows to
# preview walls) while the apply step only lands where it can work.
if(WIN32)
  target_sources(claybin PRIVATE src/windows/spawn.cpp)
  target_link_libraries(claybin PUBLIC userenv advapi32)
endif()
target_include_directories(claybin PUBLIC include)
# GNU-style flags are GNU-ONLY. MSVC takes `/W4` and treats `-Wextra` as a
# malformed `/W` -- `cl : Command line error D8021 : invalid numeric argument
# '/Wextra'` -- which kills the Windows release build on the FIRST claybin TU
# it reaches. It went unnoticed because the library only started being built
# on Windows recently (the tools were moved into the Linux block for exactly
# that reason); before that nothing compiled far enough to see these.
#
# -fno-exceptions / -fno-rtti have no MSVC spelling that means the same thing
# (/EH- changes ABI and the consumer sets /EHsc anyway), so they are simply
# not applied there. claybin's sources throw nothing and use no dynamic_cast,
# which is a property of the code rather than of the flag -- the flag is a
# guard against regressing it, and that guard still runs on every Linux and
# macOS build.
target_compile_options(claybin PRIVATE
  $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:
    -Wall -Wextra -Wconversion -Wshadow -Wold-style-cast
    -fno-exceptions -fno-rtti>
  $<$<CXX_COMPILER_ID:MSVC>:/W4 /utf-8>
)
# the whole point: no libseccomp, no libcap, no libmount. raw syscalls only.
target_link_libraries(claybin PUBLIC)

# Both CLI tools are Linux-only.
#
# claybin-audit reports what THIS host enforces, which means it calls
# probe_host() and cgroup::probe() -- the POSIX-only sources above. The
# library still builds everywhere (agentty's settings pane compiles a plan on
# macOS and Windows to preview the walls), but a tool that measures a live
# kernel has nothing to measure off one.
#
# It used to be unconditional and only linked because nobody had built the
# library for Windows far enough to reach it.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_executable(claybin-audit tools/claybin_audit.cpp)
  target_link_libraries(claybin-audit PRIVATE claybin)

  add_executable(claybin-run tools/claybin_run.cpp)
  target_link_libraries(claybin-run PRIVATE claybin)
endif()

if(CLAYBIN_TESTS)
  enable_testing()
  add_library(claybin_test_support INTERFACE)
  target_include_directories(claybin_test_support INTERFACE tests/support)

  function(claybin_test name)
    add_executable(${name} tests/${name}.cpp)
    target_link_libraries(${name} PRIVATE claybin claybin_test_support)
    target_compile_options(${name} PRIVATE
      $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall -Wextra -fno-exceptions -fno-rtti>
      $<$<CXX_COMPILER_ID:MSVC>:/W4 /utf-8>)
    add_test(NAME ${name} COMMAND ${name})
  endfunction()

  claybin_test(lattice_laws_test)
  claybin_test(fs_algebra_test)
  claybin_test(path_shape_test)
  claybin_test(bpf_emit_test)
  claybin_test(policy_typestate_test)
  claybin_test(readme_example_test)
  claybin_test(plan_test)
  claybin_test(mount_algebra_test)
  claybin_test(shapes_test)
  claybin_test(windows_backend_test)
  # the macOS backend's translation. runs on EVERY host, not just a mac --
  # compile() is pure, so a mistranslation is caught by the linux CI runner
  # rather than by a user on a laptop.
  claybin_test(macos_backend_test)
  # the apply path, which can only be meaningful on a mac: it enters a real
  # seatbelt sandbox and asserts the walls hold. skips itself elsewhere.
  claybin_test(macos_live_check)
  # the windows apply path: a real AppContainer profile, real ACLs, a real
  # confined child. windows-only, because only a windows host can mean it.
  if(WIN32)
    claybin_test(windows_live_check)
  endif()
  claybin_test(compile_fuzz_test)

  # the syscall tables get an extra translation unit: it compiles the aarch64
  # profile block on whatever host is building, so those ~130 numbers are
  # actually exercised rather than just present.
  add_executable(syscall_table_test tests/syscall_table_test.cpp
                                    tests/profiles_aarch64.cpp)
  target_link_libraries(syscall_table_test PRIVATE claybin claybin_test_support)
  target_compile_options(syscall_table_test PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall -Wextra -fno-exceptions -fno-rtti>
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /utf-8>)
  add_test(NAME syscall_table_test COMMAND syscall_table_test)

  # the aarch64 tables have never executed -- no hardware, no cross toolchain --
  # so they get a second, INDEPENDENT check: dump what they permit and resolve
  # every number through the kernel's own header. the C++ test above shares an
  # author (and any misreading) with the tables; this does not.
  add_executable(clay_dump_aarch64 tests/dump_aarch64.cpp)
  target_link_libraries(clay_dump_aarch64 PRIVATE claybin)
  add_test(NAME aarch64_audit
           COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/aarch64_audit.sh
                   $<TARGET_FILE:clay_dump_aarch64>)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    claybin_test(escape_test)
    claybin_test(escape_corpus_test)
    claybin_test(mount_test)
    # the embedder's path: spawn() with a caller-owned pipe and the caller's own
    # wait. this is what makes claybin a library rather than a subprocess, so it
    # gets a test of its own.
    claybin_test(embed_test)
    claybin_test(cgroup_test)
    claybin_test(broker_test)

    # differential conformance against the real bwrap. skips itself when bwrap
    # is not installed, because the whole point is comparing against it rather
    # than against our own idea of what it does.
    add_test(NAME conformance
             COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/tests/conformance.sh
                     $<TARGET_FILE:claybin-run>)
  endif()
endif()
