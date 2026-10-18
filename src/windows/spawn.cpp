// the windows backend's apply step. everything impure and windows-only, which
// is exactly why it is a separate file from compile.cpp -- the split mirrors
// linux (compile.cpp pure, apply.cpp + spawn.cpp impure) and macos (compile.cpp
// pure, spawn.cpp impure) so the testable surface stays the same shape on all
// three platforms.
//
// THE STRUCTURAL DIFFERENCE, up front, because it is the whole reason this file
// looks nothing like its posix siblings: on linux and macos the child applies
// its own walls after fork. on windows the walls are CreateProcess ARGUMENTS --
// token, job, mitigation policies are stamped onto the process before its
// first instruction runs, by the parent. there is no fork-and-apply, no
// async-signal-safety dance, no child-side exit protocol: a spawn here either
// returns a fully confined process or returns an error. an unconfined child
// that half-started is not a failure mode this backend has.
//
// the walls, in the order they are built:
//
//   appcontainer          default-deny token: no access to any object whose
//                         ACL does not mention our SID or a capability we hold.
//                         profile per capability-set, created (or found) here.
//   DACL grants           positive grants for the paths the policy allows:
//                         an ACE for the appcontainer SID on each grant root,
//                         inheritable, stamped in the PARENT before creation.
//   job object            memory / process-count / cpu-rate / user-time caps,
//                         plus KILL_ON_JOB_CLOSE so closing the returned handle
//                         is the kill switch for the whole tree.
//   mitigation policies   no dynamic code, no extension points, optionally no
//                         win32k, optionally no child processes.
//
#include "claybin/windows/backend.hpp"

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <userenv.h>   // CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName
#include <aclapi.h>    // SetNamedSecurityInfoW, GetNamedSecurityInfoW, EXPLICIT_ACCESS_W
#include <sddl.h>      // ConvertSidToStringSidW (diagnostics only)

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace clay::windows {
namespace {

// a HANDLE that closes exactly once. the same idea as jaal's owned_handle but
// local: claybin deliberately has no OS header in its core.
struct handle_guard {
    HANDLE h{nullptr};
    handle_guard() = default;
    explicit handle_guard(HANDLE v) : h(v) {}
    ~handle_guard() { if (h) ::CloseHandle(h); }
    handle_guard(const handle_guard&)            = delete;
    handle_guard& operator=(const handle_guard&) = delete;
    handle_guard(handle_guard&& o) noexcept : h(o.h) { o.h = nullptr; }
    handle_guard& operator=(handle_guard&& o) noexcept {
        if (this != &o) { if (h) ::CloseHandle(h); h = o.h; o.h = nullptr; }
        return *this;
    }
    HANDLE get() const noexcept { return h; }
    HANDLE release() noexcept { HANDLE t = h; h = nullptr; return t; }
    explicit operator bool() const noexcept { return h != nullptr; }
};

// a LocalAlloc'd block (SIDs, ACLs) -- LocalFree, not CloseHandle. a second
// guard because the two allocators are not interchangeable and a PSID in a
// HANDLE guard would be freed with the wrong call.
struct local_guard {
    void* p{nullptr};
    local_guard() = default;
    explicit local_guard(void* v) : p(v) {}
    ~local_guard() { if (p) ::LocalFree(p); }
    local_guard(const local_guard&)            = delete;
    local_guard& operator=(const local_guard&) = delete;
    local_guard(local_guard&& o) noexcept : p(o.p) { o.p = nullptr; }
    local_guard& operator=(local_guard&& o) noexcept {
        if (this != &o) { if (p) ::LocalFree(p); p = o.p; o.p = nullptr; }
        return *this;
    }
    void* get() const noexcept { return p; }
    void* release() noexcept { void* t = p; p = nullptr; return t; }
    explicit operator bool() const noexcept { return p != nullptr; }
};

Error win_error(std::string_view mechanism) {
    return Error{Errc::io_error, mechanism, static_cast<int>(::GetLastError())};
}

std::wstring widen(std::string_view s) {
    if (s.empty()) return {};
    const int n = ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                                        nullptr, 0);
    if (n <= 0) return {};
    std::wstring out(static_cast<std::size_t>(n), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), out.data(), n);
    return out;
}

std::string narrow(const wchar_t* s) {
    if (!s) return {};
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, s, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    std::string out(static_cast<std::size_t>(n - 1 > 0 ? n - 1 : 0), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, s, -1, out.data(), n, nullptr, nullptr);
    return out;
}

// quote one argument by CommandLineToArgvW rules, so the child's C runtime
// recovers it exactly.
std::string quote_arg(std::string_view arg) {
    const bool needs = arg.empty() ||
                       arg.find_first_of(" \t\"") != std::string_view::npos;
    if (!needs) return std::string{arg};
    std::string out{"\""};
    size_t backslashes = 0;
    for (const char c : arg) {
        if (c == '\\') { ++backslashes; continue; }
        if (c == '"') {
            // a quote is preceded by 2n backslashes doubled, plus itself escaped
            out.append(backslashes * 2 + 1, '\\');
            out.push_back('"');
        } else {
            out.append(backslashes, '\\');
            out.push_back(c);
        }
        backslashes = 0;
    }
    // trailing backslashes before the closing quote are doubled
    out.append(backslashes * 2, '\\');
    out.push_back('"');
    return out;
}

// ── appcontainer profile management ────────────────────────────────────────
//
// a profile name is at most 64 chars of [A-Za-z0-9.], and a profile's
// capability set is FIXED AT CREATION. spawn() is called with a different
// capability set per policy (network on / network off), so the profile name
// carries a hash of the capability names: one profile per distinct set, found
// again on the next run, never silently reused with the wrong caps.

std::string sanitize_profile_name(std::string_view raw) {
    std::string out;
    out.reserve(raw.size());
    for (const char c : raw) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.')
            out.push_back(c);
        else
            out.push_back('_');
    }
    return out;
}

std::string capability_profile_suffix(const std::vector<std::string>& caps) {
    // FNV-1a over the sorted capability names. not cryptographic; it only has
    // to keep two different capability sets from sharing one profile name.
    std::uint64_t h = 1469598103934665603ull;
    for (const auto& c : caps) {
        for (const char ch : c) { h ^= static_cast<std::uint8_t>(ch); h *= 1099511628211ull; }
        h ^= 0xff; h *= 1099511628211ull;
    }
    char buf[17]{};
    for (int i = 0; i < 16; ++i) buf[i] = "0123456789abcdef"[(h >> (60 - 4 * i)) & 0xf];
    return std::string{buf};
}

// DeriveCapabilitySidsFromName is in kernelbase and is absent from some
// import libraries, so it is resolved at run time. absent means win7-era or
// a stripped down system: we fail closed on network grants rather than
// building a capability SID from memory.
using DeriveCapabilitySidsFn =
    HRESULT (WINAPI*)(PCWSTR, PSID_AND_ATTRIBUTES*, DWORD*, PSID*, DWORD*);

// PSID is a void*; mingw declares the derive call with PSID*, which resolves
// to void** -- same bytes, wrong type for our guards.
using DeriveAppContainerSidFn = HRESULT (WINAPI*)(PCWSTR, void**);

// the function-local const static is thread-safe-once initialization
// (C++11), and reads as `const` to the vendored-library lint, which rejects
// mutable statics in the libraries it watches.
const DeriveCapabilitySidsFn kDeriveCapabilitySids = []() -> DeriveCapabilitySidsFn {
    HMODULE kb = ::GetModuleHandleW(L"kernelbase.dll");
    if (!kb) kb = ::LoadLibraryW(L"kernelbase.dll");
    return kb ? reinterpret_cast<DeriveCapabilitySidsFn>(
                    reinterpret_cast<void*>(::GetProcAddress(kb, "DeriveCapabilitySidsFromName")))
              : nullptr;
}();

DeriveCapabilitySidsFn derive_capability_sids_fn() {
    return kDeriveCapabilitySids;
}

// DeriveAppContainerSidFromAppContainerName in the import library resolves to
// a stub that fails with ERROR_NO_TOKEN (a live check on this very host), so
// it is loaded from userenv at run time -- the derivation has to work when a
// second process with the same capability set finds the first run's profile.
const DeriveAppContainerSidFn kDeriveAppContainerSid = []() -> DeriveAppContainerSidFn {
    HMODULE ue = ::GetModuleHandleW(L"userenv.dll");
    if (!ue) ue = ::LoadLibraryW(L"userenv.dll");
    return ue ? reinterpret_cast<DeriveAppContainerSidFn>(
                    reinterpret_cast<void*>(::GetProcAddress(
                        ue, "DeriveAppContainerSidFromAppContainerName")))
              : nullptr;
}();

DeriveAppContainerSidFn derive_appcontainer_sid_fn() {
    return kDeriveAppContainerSid;
}

// the canonical network capability names. compile() says only `allow_network`;
// mapping that intent to names is the apply step's job, which keeps the pure
// compiler free of windows vocabulary.
constexpr const wchar_t* kNetworkCapabilities[] = {
    L"internetClient",              // outbound to the internet
    L"privateNetworkClientServer",  // loopback + LAN, so a local dev server works
};

// the access-mask bits this file consults, restated from winnt.h. compile.cpp
// has its own copy because it must build on every host; only windows includes
// this file, but these are still spelled here rather than in the header so
// the header stays free of windows vocabulary.
constexpr std::uint32_t kFileWriteData = 0x0002;
constexpr std::uint32_t kFileAppendData = 0x0004;
constexpr std::uint32_t kFileWriteAttributes = 0x0100;
constexpr std::uint32_t kFileDeleteChild = 0x0040;
constexpr std::uint32_t kDelete = 0x00010000;

// mingw-w64's winbase.h carries the attribute MACROS but not the mitigation
// VALUE defines (they live in the SDK's WinBase.h). defined here with the
// exact values from the Windows 10 SDK, guarded, so a header that does grow
// them stays in charge.
#ifndef PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON \
    (UINT64_C(0x00000001) << 36)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON \
    (UINT64_C(0x00000001) << 28)
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON \
    (UINT64_C(0x00000001) << 32)
#endif
#ifndef PROCESS_CREATION_CHILD_PROCESS_RESTRICTED
#define PROCESS_CREATION_CHILD_PROCESS_RESTRICTED 0x01
#endif
#ifndef LUA_TOKEN
#define LUA_TOKEN (0x00000004)
#endif

struct container_context {
    local_guard profile_sid;  // the package SID; LocalFree'd, not CloseHandle'd
    std::vector<BYTE> cap_blob;
    std::vector<SID_AND_ATTRIBUTES> caps;
    // the ACL entries are stamped for THIS sid; kept for diagnostics
    std::string sid_string;
};

// create or find the appcontainer profile for this capability set.
// on failure: an error, never a silently uncontained process.
Result<container_context> make_container(const Compiled& c) {
    container_context ctx;

    std::vector<std::string> caps = c.capabilities;
    if (c.allow_network) {
        for (const wchar_t* w : kNetworkCapabilities)
            caps.push_back(narrow(w));
    }
    std::sort(caps.begin(), caps.end());
    caps.erase(std::unique(caps.begin(), caps.end()), caps.end());

    const std::string base = sanitize_profile_name(
        c.container_name.empty() ? "claybin.sandbox" : c.container_name);
    const std::string name = (base + "." + capability_profile_suffix(caps))
                                 .substr(0, 64);  // USERENV: max 64 chars

    const std::wstring wname = widen(name);

    // DeriveCapabilitySidsFromName for every capability we mean to hold. The
    // well-known ones (internetClient & co) resolve here; an unknown name
    // fails and spawn fails closed rather than granting nothing silently.
    //
    // SIDs are copied into cap_blob FIRST, all of them, and the SID_AND_
    // ATTRIBUTES pointers are built AFTER the vector reaches its final size:
    // a push_back that reallocs would invalidate every pointer already stored
    // -- the classic vector-of-pointers-into-itself bug, and a silent one
    // until the token builder reads a freed SID.
    if (!caps.empty()) {
        auto fn = derive_capability_sids_fn();
        if (!fn)
            return std::unexpected(Error{Errc::unsupported, "appcontainer: "
                "DeriveCapabilitySidsFromName unavailable; cannot grant capabilities"});
        for (const auto& cap : caps) {
            const std::wstring wcap = widen(cap);
            PSID_AND_ATTRIBUTES attr = nullptr;
            DWORD attr_count = 0;
            PSID group_sids = nullptr;
            DWORD group_count = 0;
            const HRESULT hr = fn(wcap.c_str(), &attr, &attr_count,
                                  &group_sids, &group_count);
            if (FAILED(hr) || !attr || attr_count == 0 || !attr[0].Sid) {
                if (group_sids) ::LocalFree(group_sids);
                if (attr) ::LocalFree(attr);
                return std::unexpected(Error{Errc::invalid_policy, "appcontainer: "
                    "capability name not derivable", static_cast<int>(hr)});
            }
            // THE capability SID is attr[0].Sid. The `sids` out-param is the
            // capability's GROUP list (r/o membership granted alongside) and
            // is several hundred bytes of variable-length data -- treating its
            // first entry as the capability SID produces a malformed SID that
            // CreateAppContainerProfile rejects with RPC_S_INVALID_BOUND. The
            // group list is not wanted here: the profile carries exactly the
            // named capability, nothing ambient.
            const PSID cap_sid = attr[0].Sid;
            const DWORD bytes = ::GetSidLengthRequired(
                static_cast<UCHAR>(*::GetSidSubAuthorityCount(cap_sid)));
            const size_t base_off = ctx.cap_blob.size();
            ctx.cap_blob.resize(base_off + bytes);
            std::memcpy(ctx.cap_blob.data() + base_off, cap_sid, bytes);
            ::LocalFree(attr);
            ::LocalFree(group_sids);
        }
        // the blob is final now; safe to point into it
        ctx.caps.reserve(ctx.cap_blob.size() / sizeof(SID));
        size_t off = 0;
        while (off < ctx.cap_blob.size()) {
            SID_AND_ATTRIBUTES a{};
            a.Sid = ctx.cap_blob.data() + off;
            a.Attributes = SE_GROUP_ENABLED;
            ctx.caps.push_back(a);
            off += ::GetSidLengthRequired(
                static_cast<UCHAR>(*::GetSidSubAuthorityCount(
                    reinterpret_cast<PSID>(ctx.cap_blob.data() + off))));
        }
    }

    // create; if a profile with this exact name already exists it was created
    // by a previous run with the SAME capability hash, so deriving its SID is
    // equivalent -- the caps are baked into the name.
    PSID package_sid = nullptr;
    const HRESULT hr = ::CreateAppContainerProfile(
        wname.c_str(), wname.c_str(), L"claybin sandbox",
        ctx.caps.empty() ? nullptr : ctx.caps.data(),
        static_cast<DWORD>(ctx.caps.size()), &package_sid);
#ifdef CLAYBIN_SPAWN_TRACE
    std::fprintf(stderr, "[claybin] profile name='%s' hr=0x%08lx caps=%zu\n",
                 name.c_str(), static_cast<unsigned long>(hr), ctx.caps.size());
#endif
    if (FAILED(hr)) {
#ifdef CLAYBIN_SPAWN_TRACE
        std::fprintf(stderr, "[claybin] code=%luFacility=%lu\n",
                     static_cast<unsigned long>(HRESULT_CODE(hr)),
                     static_cast<unsigned long>(HRESULT_FACILITY(hr)));
#endif
        if (HRESULT_CODE(hr) != ERROR_ALREADY_EXISTS) {
            return std::unexpected(Error{Errc::permission_denied, "appcontainer: "
                "CreateAppContainerProfile failed", static_cast<int>(hr)});
        }
        // Profile from a previous run with the same capability set. Derive
        // through the RUN-TIME binding: the import-lib stub fails with
        // ERROR_NO_TOKEN, and the probe's leftover profile makes this path
        // the one every second run takes.
        auto derive = derive_appcontainer_sid_fn();
        if (!derive || FAILED(derive(wname.c_str(), &package_sid)) || !package_sid) {
            return std::unexpected(Error{Errc::permission_denied, "appcontainer: "
                "profile exists but its SID is not derivable",
                static_cast<int>(::GetLastError())});
        }
    }
    ctx.profile_sid = local_guard{package_sid};
    return ctx;
}

// ── DACL grants ────────────────────────────────────────────────────────────
//
// one ACE per grant root, for the appcontainer package SID, inheritable.
// SetNamedSecurityInfoW on the ROOT (not a tree walk): inheritable ACEs
// propagate to descendants automatically, including objects created later,
// which is the closest an ACL model gets to landlock's subtree rule.
//
// merging, not replacing: the guest still needs whatever the DACL already
// allowed (the user's own files), and a PROTECTED ACL here would break things
// we were never asked to break.

Result<void> stamp_acl(const std::string& path, std::uint32_t mask, PSID grantee) {
    const std::wstring wpath = widen(path);
    if (wpath.empty()) return {};

    // a grant on a path that does not exist yet is a common shape: a build
    // tool's output dir, the mapped /tmp root. the ACE must exist BEFORE the
    // first child write lands there, so the grant creates the directory --
    // the same thing a workspace checkout does on first use. a path that
    // cannot be created is an error, not a silent skip: the policy said this
    // is a boundary and half of one is a lie.
    if (DWORD attrs = ::GetFileAttributesW(wpath.c_str());
        attrs == INVALID_FILE_ATTRIBUTES) {
        if (!::CreateDirectoryW(wpath.c_str(), nullptr) &&
            ::GetLastError() != ERROR_ALREADY_EXISTS) {
            return std::unexpected(Error{Errc::io_error,
                                         "acl: grant path cannot be created",
                                         static_cast<int>(::GetLastError())});
        }
    }

    PACL existing = nullptr;
    // GetNamedSecurityInfoW allocations are LocalFree'd; the DACL is copied
    // into a vector so SetEntriesInAclW reads a copy that outlives the SD,
    // which cannot -- a PACL pointing into a freed descriptor is the classic
    // use-after-free of this API.
    {
        PSECURITY_DESCRIPTOR sd = nullptr;
        const DWORD g = ::GetNamedSecurityInfoW(
            const_cast<LPWSTR>(wpath.c_str()), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION, nullptr, nullptr, &existing, nullptr, &sd);
#ifdef CLAYBIN_SPAWN_TRACE
        std::fprintf(stderr, "[claybin] acl get '%s' g=%lu gle=%lu\n",
                     path.c_str(), static_cast<unsigned long>(g),
                     static_cast<unsigned long>(::GetLastError()));
#endif
        if (g != ERROR_SUCCESS) {
            if (sd) ::LocalFree(sd);
            return std::unexpected(Error{Errc::permission_denied,
                                         "acl: cannot read existing DACL",
                                         static_cast<int>(g)});
        }
        // keep the descriptor alive until we have copied the ACL below
        const std::uint16_t acl_bytes = existing ? existing->AclSize : 0;
        std::vector<BYTE> acl_copy(acl_bytes);
        if (acl_bytes) std::memcpy(acl_copy.data(), existing, acl_bytes);
        ::LocalFree(sd);
        existing = acl_bytes ? reinterpret_cast<PACL>(acl_copy.data()) : nullptr;

        EXPLICIT_ACCESSW ea{};
        ea.grfAccessPermissions = mask;
        ea.grfAccessMode = GRANT_ACCESS;
        ea.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
        ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        ea.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
        ea.Trustee.ptstrName = reinterpret_cast<LPWCH>(grantee);

        PACL merged = nullptr;
        const DWORD m = ::SetEntriesInAclW(1, &ea, existing, &merged);
        if (m != ERROR_SUCCESS || !merged) {
            if (merged) ::LocalFree(merged);
            return std::unexpected(Error{Errc::permission_denied,
                                         "acl: cannot merge ACE", static_cast<int>(m)});
        }
        const DWORD s = ::SetNamedSecurityInfoW(
            const_cast<LPWSTR>(wpath.c_str()), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION, nullptr, nullptr, merged, nullptr);
        ::LocalFree(merged);
        if (s != ERROR_SUCCESS) {
            return std::unexpected(Error{Errc::permission_denied,
                                         "acl: cannot write DACL", static_cast<int>(s)});
        }

        // write grants need the object's mandatory label at Low as well: an
        // appcontainer token is Low integrity, and every user-created object
        // is Medium with the default NO-WRITE-UP policy -- the integrity
        // check fires BEFORE the DACL is consulted, so the package-SID ACE
        // above never gets a chance to matter. this is the same step every
        // real appcontainer host takes for its writable directories (chrome's
        // profile, UWP's local state): label Low, ACE for the package SID.
        // medium-IL processes are unaffected: they sit ABOVE low and
        // write-down is never restricted, so the user's own tools keep full
        // access to their workspace.
        const bool writes = (mask & (kFileWriteData | kFileAppendData |
                                     kFileWriteAttributes | kFileDeleteChild |
                                     kDelete)) != 0;
        if (writes) {
            BYTE low_buf[SECURITY_MAX_SID_SIZE]{};
            DWORD low_size = sizeof(low_buf);
            if (::CreateWellKnownSid(WinLowLabelSid, nullptr, low_buf, &low_size)) {
                // the label is a SACL ACE, not a bare SID: build the one-ACE
                // mandatory-label ACL and install it as the object's SACL.
                // NO_WRITE_UP alone: a Low token cannot write a Medium object,
                // which is exactly the rule an appcontainer lives under; the
                // object's existing read/exec behaviour stays untouched.
                constexpr DWORD kLabelAclSize =
                    sizeof(ACL) + sizeof(SYSTEM_MANDATORY_LABEL_ACE) + SECURITY_MAX_SID_SIZE;
                alignas(DWORD) BYTE label_buf[kLabelAclSize]{};
                auto* label_acl = reinterpret_cast<PACL>(label_buf);
                if (::InitializeAcl(label_acl, kLabelAclSize, ACL_REVISION) &&
                    ::AddMandatoryAce(label_acl, ACL_REVISION, 0,
                                      SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
                                      reinterpret_cast<PSID>(low_buf))) {
                    const DWORD l = ::SetNamedSecurityInfoW(
                        const_cast<LPWSTR>(wpath.c_str()), SE_FILE_OBJECT,
                        LABEL_SECURITY_INFORMATION, nullptr, nullptr,
                        nullptr, label_acl);
                    if (l != ERROR_SUCCESS) {
                        return std::unexpected(Error{Errc::permission_denied,
                                                     "acl: cannot set mandatory label",
                                                     static_cast<int>(l)});
                    }
                }
            }
        }
    }
    return {};
}

// ── environment block ──────────────────────────────────────────────────────
//
// CreateProcess wants the block sorted case-insensitively by name and
// terminated by a double NUL. a caller that guesses at that order gets
// silently-dropped variables, so the sort happens here, once, from the same
// char* strings the posix backends take.
std::vector<wchar_t> build_env_block(const char* const* envp) {
    if (!envp) return {};
    struct ci_less {
        bool operator()(const std::wstring& a, const std::wstring& b) const noexcept {
            return ::_wcsicmp(a.c_str(), b.c_str()) < 0;
        }
    };
    std::map<std::wstring, std::wstring, ci_less> vars;
    for (const char* const* e = envp; *e; ++e) {
        const std::string_view kv{*e};
        const auto eq = kv.find('=');
        if (eq == std::string_view::npos) continue;
        vars[widen(kv.substr(0, eq))] = widen(kv.substr(eq + 1));
    }
    std::vector<wchar_t> block;
    for (const auto& [k, v] : vars) {
        block.insert(block.end(), k.begin(), k.end());
        block.push_back(L'=');
        block.insert(block.end(), v.begin(), v.end());
        block.push_back(L'\0');
    }
    if (block.empty()) return {};
    block.push_back(L'\0');
    return block;
}

// ── the NUL device ─────────────────────────────────────────────────────────
handle_guard open_nul(bool inheritable) {
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, inheritable ? TRUE : FALSE};
    HANDLE h = ::CreateFileW(L"NUL", GENERIC_READ | GENERIC_WRITE,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, &sa,
                             OPEN_EXISTING, 0, nullptr);
    return handle_guard(h);
}

handle_guard dup_inheritable(HANDLE parent) {
    HANDLE dup = nullptr;
    if (!::DuplicateHandle(::GetCurrentProcess(), parent, ::GetCurrentProcess(), &dup,
                           0, TRUE, DUPLICATE_SAME_ACCESS))
        return handle_guard{};
    return handle_guard(dup);
}

// ── the job object ─────────────────────────────────────────────────────────
//
// every limit the compiled plan asks for, in one SetInformationJobObject
// call each. KILL_ON_JOB_CLOSE unconditionally: the returned handle is the
// kill switch, and a caller that leaks it leaks a running tree otherwise.
Result<HANDLE> make_job(const Compiled& c) {
    HANDLE job = ::CreateJobObjectW(nullptr, nullptr);
    if (!job) return std::unexpected(win_error("job: CreateJobObjectW"));

    JOBOBJECT_BASIC_LIMIT_INFORMATION basic{};
    basic.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (c.active_process_limit) {
        basic.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        basic.ActiveProcessLimit = c.active_process_limit;
    }
    if (c.user_time_limit_100ns) {
        basic.LimitFlags |= JOB_OBJECT_LIMIT_JOB_TIME;
        basic.PerJobUserTimeLimit.QuadPart =
            static_cast<LONGLONG>(c.user_time_limit_100ns);
    }

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION ext{};
    ext.BasicLimitInformation = basic;
    if (c.memory_limit_bytes) {
        ext.BasicLimitInformation.LimitFlags |=
            JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_MEMORY;
        ext.ProcessMemoryLimit = c.memory_limit_bytes;
        ext.JobMemoryLimit = c.memory_limit_bytes;
    }

    if (!::SetInformationJobObject(job, JobObjectExtendedLimitInformation,
                                   &ext, sizeof(ext))) {
        const Error e = win_error("job: SetInformationJobObject(limits)");
        ::CloseHandle(job);
        return std::unexpected(e);
    }

    if (c.cpu_rate_percent) {
        JOBOBJECT_CPU_RATE_CONTROL_INFORMATION cpu{};
        cpu.ControlFlags = JOB_OBJECT_CPU_RATE_CONTROL_ENABLE |
                           JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        // per-ten-thousand: 1% is the floor, 100% is 10000.
        std::uint64_t rate = c.cpu_rate_percent * 100;
        if (rate < 1000) rate = 1000;
        if (rate > 10000) rate = 10000;
        cpu.CpuRate = static_cast<DWORD>(rate);
        if (!::SetInformationJobObject(job, JobObjectCpuRateControlInformation,
                                       &cpu, sizeof(cpu))) {
            const Error e = win_error("job: SetInformationJobObject(cpu rate)");
            ::CloseHandle(job);
            return std::unexpected(e);
        }
    }
    return job;
}

}  // namespace

// the probe verdict is CACHED for the process lifetime, and the cache is
// written by the FIRST call. this is not an optimization: on insider build
// 26300 the restricted+appcontainer child probe is process-warmth dependent
// -- early calls report death (rt=0), later calls (after ~20 real spawns)
// report success (rt=1). a compile() that re-probes per call can therefore
// see a verdict that contradicts the one the caller just measured, and build
// a wall that kills every guest. the first answer is also the COLDEST, i.e.
// the most representative of what a fresh guest faces, so it is the one the
// process sticks with.
//
// the function-local const static is the whole mechanism: C++11 guarantees
// its initialization is thread-safe and happens exactly once, which keeps
// this file inside the vendored-library rules (no <atomic>, no mutable
// statics).
HostCapabilities cached_host_probe() {
    static const HostCapabilities cached = probe_host_uncached();
    return cached;
}

// ── probe_host, windows side ───────────────────────────────────────────────
//
// the same discipline as the linux and macos probes: a capability that reads
// as present but fails on use is worse than absence, because a caller's Auto
// mode then degrades silently instead of loudly. so each answer comes from
// actually doing the thing, cheaply, once.
HostCapabilities probe_host_uncached() {
    HostCapabilities h = HostCapabilities::none();
    OSVERSIONINFOW vi{};
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (!::GetVersionExW(&vi)) return h;
    h.build = vi.dwBuildNumber;

    // job objects: create one. NT has had them since the beginning; creating
    // costs microseconds and proves it rather than guessing.
    if (HANDLE j = ::CreateJobObjectW(nullptr, nullptr)) {
        ::CloseHandle(j);
        h.job_objects = true;
    }

    // mitigation policies: the attribute list API is the gate. updating with
    // a DEFER policy is a no-op on the child side and proves the plumbing.
    {
        SIZE_T size = 0;
        ::InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
        std::vector<BYTE> buf(size);
        auto* list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buf.data());
        if (::InitializeProcThreadAttributeList(list, 1, 0, &size)) {
            DWORD64 defer = 0;
            h.mitigation_policies = ::UpdateProcThreadAttribute(
                list, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                &defer, sizeof(defer), nullptr, nullptr) != FALSE;
            ::DeleteProcThreadAttributeList(list);
        }
    }

        // restricted tokens: CreateRestrictedToken on a copy of our own token,
        // then PROOF under the REAL conditions a guest will face: the
        // appcontainer attribute is part of every claybin spawn, so the probe
        // child carries it too. Measured on this host (insider build 26300): a
        // restricted token ALONE starts cleanly, but restricted + appcontainer
        // kills the child during ntdll init (0xc0000142) -- a capability that
        // reads as present and fails on use is worse than absence, so the probe
        // asks the only question that matters: does a child run under exactly
        // the walls the backend builds? When it does not, the read wall is
        // reported absent and spawn falls back to the appcontainer-only path,
        // which is the weaker but honest boundary.
        {
            HANDLE tok = nullptr;
            if (::OpenProcessToken(::GetCurrentProcess(),
                                   TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY |
                                   TOKEN_QUERY, &tok)) {
                handle_guard tok_guard{tok};
                DWORD len = 0;
                std::vector<BYTE> ub;
                if (::GetTokenInformation(tok, TokenUser, nullptr, 0, &len) || len) {
                    ub.resize(len);
                    if (::GetTokenInformation(tok, TokenUser, ub.data(), len, &len)) {
                        auto* tu = reinterpret_cast<TOKEN_USER*>(ub.data());
                        // the restricted list must be the PRODUCTION one, or the
                        // probe proves the wrong token. spawn() subtracts with
                        // BUILTIN\Users + Everyone (the read wall: neither grants
                        // read on the user's own files, so the user-SID grants stop
                        // counting). a probe list of [user SID] is nearly a no-op
                        // restriction -- a child under it can pass while every
                        // production child dies (measured: exactly that on insider
                        // build 26300 -- 0xc0000142 in ntdll init, reproducibly,
                        // with the real list but never with the probe's).
                        SID_AND_ATTRIBUTES prod_list[2] = {};
                        std::vector<BYTE> sids_blob(2 * SECURITY_MAX_SID_SIZE);
                        DWORD n_prod = 0;
                        const WELL_KNOWN_SID_TYPE types[2] = {
                            WinBuiltinUsersSid, WinWorldSid};
                        for (int i = 0; i < 2; ++i) {
                            DWORD sid_len = SECURITY_MAX_SID_SIZE;
                            auto* sid = reinterpret_cast<PSID>(
                                sids_blob.data() + i * SECURITY_MAX_SID_SIZE);
                            if (!::CreateWellKnownSid(types[i], nullptr, sid, &sid_len))
                                continue;
                            prod_list[n_prod++] = SID_AND_ATTRIBUTES{sid, 0};
                        }
                        SID_AND_ATTRIBUTES fallback_list{tu->User.Sid, 0};
                        SID_AND_ATTRIBUTES* list = prod_list;
                        DWORD list_n = n_prod;
                        if (n_prod != 2) { list = &fallback_list; list_n = 1; }
                        HANDLE rt = nullptr;
                        if (::CreateRestrictedToken(tok, 0, 0, nullptr, 0, nullptr,
                                                    list_n, list, &rt)) {
                            handle_guard rt_guard{rt};
                            // the probe's attribute list: the SAME appcontainer
                            // attribute spawn() will add. A profile is created and
                            // deleted here -- the throwaway "claybin.probe".
                            PSID pkg = nullptr;
                            const HRESULT hr = ::CreateAppContainerProfile(
                                L"claybin.probe", L"claybin probe", L"capability probe",
                                nullptr, 0, &pkg);
                            if (SUCCEEDED(hr) && pkg) {
                                h.app_container = true;
                                h.lowbox_network = true;
                                SIZE_T asize = 0;
                                ::InitializeProcThreadAttributeList(nullptr, 1, 0, &asize);
                                std::vector<BYTE> abuf(asize);
                                auto* alist = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(abuf.data());
                                if (::InitializeProcThreadAttributeList(alist, 1, 0, &asize)) {
                                    SECURITY_CAPABILITIES sc{};
                                    sc.AppContainerSid = pkg;
                                    if (::UpdateProcThreadAttribute(
                                            alist, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                                            &sc, sizeof(sc), nullptr, nullptr)) {
                                        STARTUPINFOEXW si{};
                                        si.StartupInfo.cb = sizeof(si);
                                        si.lpAttributeList = alist;
                                        PROCESS_INFORMATION pi{};
                                        // EXACTLY the production shape: lpApplicationName=nullptr
                                        // (command line only), inheritable handles TRUE, an env
                                        // block, a workdir, and — the part that turned out to be
                                        // the discriminator on insider builds — CREATE_SUSPENDED
                                        // with the job assignment BEFORE the first instruction,
                                        // exactly what spawn() does. A non-suspended child passes
                                        // here while every suspended one dies in ntdll init with
                                        // 0xc0000142, which reads as a capability that isn't one.
                                        // the command line lives in a WRITABLE buffer: with
                                        // lpApplicationName=nullptr CreateProcess parses (and
                                        // modifies) it, so a string literal here is an AV.
                                        const wchar_t probe_env[] = L"SystemRoot=C:\\Windows\0";
                                        wchar_t probe_cmdline[] = L"cmd.exe /d /s /c \"exit 7\"";
                                        // the handle list, same as production step 4: with
                                        // EXTENDED_STARTUPINFO the child only gets what is listed.
                                        HANDLE probe_std[3] = {
                                            ::GetStdHandle(STD_INPUT_HANDLE),
                                            ::GetStdHandle(STD_OUTPUT_HANDLE),
                                            ::GetStdHandle(STD_ERROR_HANDLE)};
                                        STARTUPINFOEXW psi{};
                                        psi.StartupInfo.cb = sizeof(psi);
                                        psi.lpAttributeList = alist;
                                        if (::UpdateProcThreadAttribute(
                                                alist, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                                                probe_std, sizeof(probe_std), nullptr, nullptr)) {
                                            psi.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
                                            psi.StartupInfo.hStdInput  = probe_std[0];
                                            psi.StartupInfo.hStdOutput = probe_std[1];
                                            psi.StartupInfo.hStdError  = probe_std[2];
                                            HANDLE probe_job = ::CreateJobObjectW(nullptr, nullptr);
                                            JOBOBJECT_BASIC_LIMIT_INFORMATION jb{};
                                            jb.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                                            ::SetInformationJobObject(
                                                probe_job, JobObjectBasicLimitInformation,
                                                &jb, sizeof(jb));
                                            // the child is measured THREE times: on insider
                                            // build 26300 the restricted+appcontainer combo dies
                                            // in ntdll init NONDETERMINISTICALLY (measured: the
                                            // same process reported both verdicts minutes apart,
                                            // and a single-run verdict made spawn() build a wall
                                            // that killed every real guest). all runs must exit 7;
                                            // one death is enough to call the wall unbuildable,
                                            // because a guest that sometimes dies is worse than
                                            // no read wall.
                                            h.restricted_tokens = true;
                                            for (int run = 0; run < 3; ++run) {
                                                const BOOL ok = ::CreateProcessAsUserW(
                                                    rt, nullptr, probe_cmdline,
                                                    nullptr, nullptr, TRUE,
                                                    CREATE_SUSPENDED | CREATE_NO_WINDOW |
                                                        CREATE_UNICODE_ENVIRONMENT |
                                                        EXTENDED_STARTUPINFO_PRESENT,
                                                    const_cast<LPVOID>(
                                                        static_cast<const void*>(probe_env)),
                                                    const_cast<LPWSTR>(L"C:\\Windows"),
                                                    &psi.StartupInfo, &pi);
                                                if (!ok) { h.restricted_tokens = false; break; }
                                                if (!::AssignProcessToJobObject(probe_job, pi.hProcess)) {
                                                    ::TerminateProcess(pi.hProcess, 1);
                                                    ::CloseHandle(pi.hThread);
                                                    ::CloseHandle(pi.hProcess);
                                                    h.restricted_tokens = false;
                                                    break;
                                                }
                                                ::ResumeThread(pi.hThread);
                                                ::WaitForSingleObject(pi.hProcess, 10000);
                                                DWORD code = 0;
                                                ::GetExitCodeProcess(pi.hProcess, &code);
                                                if (code != 7) { h.restricted_tokens = false; break; }
                                            }
                                            ::CloseHandle(probe_job);
                                        }
                                    }
                                    ::DeleteProcThreadAttributeList(alist);
                                }
                                ::LocalFree(pkg);
                                ::DeleteAppContainerProfile(L"claybin.probe");
                            }
                        }
                    }
                }
            }
        }

    // appcontainer: the honest probe CREATES a throwaway profile and deletes
    // it, because "the API exists" and "this token may create one" are
    // different answers (services, runas tokens and enterprise policy all
    // say no in their own way). a normal appcontainer is sufficient for every
    // wall this backend builds; the caps-less no-network case blocks socket
    // creation on normal containers just as it does on lowbox ones, so the
    // lowbox flag carries that claim rather than a literal LPAC check.
    {
        PSID sid = nullptr;
        const HRESULT hr = ::CreateAppContainerProfile(
            L"claybin.probe", L"claybin probe", L"capability probe",
            nullptr, 0, &sid);
        if (SUCCEEDED(hr) && sid) {
            h.app_container = true;
            h.lowbox_network = true;
            ::LocalFree(sid);
            ::DeleteAppContainerProfile(L"claybin.probe");
        }
    }
    return h;
}

// ── spawn ──────────────────────────────────────────────────────────────────
Result<Spawned> spawn(Compiled c, const SpawnRequest& req) {
    if (!req.program || !req.argv) return std::unexpected(
        Error{Errc::invalid_policy, "spawn: no program"});

    Spawned out;

    // ── 1. the container ──────────────────────────────────────────
    container_context cc;
    if (c.use_app_container) {
        auto made = make_container(c);
        if (!made) return std::unexpected(made.error());
        cc = std::move(*made);
        // narrow the SID for the error paths and diagnostics
        LPWSTR str = nullptr;
        if (::ConvertSidToStringSidW(cc.profile_sid.get(), &str) && str) {
            cc.sid_string = narrow(str);
            ::LocalFree(str);
        }
    }

    // ── 2. the positive grants, in the parent, before the child exists ────
    //
    // this is the apply step's whole reason to be a separate pass: on posix
    // the grants happen inside the child after fork; here they are property
    // mutations on host objects and MUST precede creation, or the child's
    // first instruction already runs against a wall it cannot pass.
    if (c.acls_applied && cc.profile_sid) {
        for (const auto& [path, mask] : c.acl_grants) {
            if (auto st = stamp_acl(path, mask, cc.profile_sid.get()); !st) {
                // distinguish the two failure classes honestly: a write to a
                // path this token does not own is a HOST limitation (the
                // daemon/agent runs unprivileged), not a policy refusal.
                // compile() reported acls_applied on the strength of the
                // probe's ability to read DACLs, which overpromised. degrading
                // to default-deny keeps the walls that DO hold (appcontainer,
                // job, mitigations) and reports fs as weaker -- a sandbox
                // that half-applies and says so beats one that lies.
                if (st.error().sys_errno == ERROR_ACCESS_DENIED) {
                    c.acls_applied = false;
                    break;
                }
                return std::unexpected(st.error());
            }
        }
    }

    // ── 3. the job ────────────────────────────────────────────────────────
    handle_guard job;
    {
        auto j = make_job(c);
        if (!j) return std::unexpected(j.error());
        job = handle_guard{*j};
    }

    // ── 4. standard handles ───────────────────────────────────────────
    //
    // the caller's handles are duplicated inheritable rather than used in
    // place: the child gets its own copies, the caller keeps ownership of
    // its originals, and the FdMap stays borrow-only like Command::FdMap.
    // the guards live at function scope so the duplicates survive until
    // CreateProcess has consumed them, and close when spawn returns.
    HANDLE child_std[3] = {nullptr, nullptr, nullptr};
    handle_guard std_dups[3];
    {
        // FdMap first, so an explicit mapping wins over the sentinel fields.
        for (int i = 0; i < req.fd_count && i < SpawnRequest::kMaxFdMaps; ++i) {
            const auto& m = req.fds[i];
            if (m.child_fd < 0 || m.child_fd > 2 || !m.parent) continue;
            std_dups[m.child_fd] = dup_inheritable(static_cast<HANDLE>(m.parent));
        }
        for (int i = 0; i < 3; ++i) {
            if (!std_dups[i]) {
                const int req_fd = i == 0 ? req.stdin_fd
                                 : i == 1 ? req.stdout_fd : req.stderr_fd;
                if (req_fd == SpawnRequest::kDevNull) {
                    std_dups[i] = open_nul(true);
                } else if (req_fd == -1) {
                    const HANDLE cur = i == 0 ? ::GetStdHandle(STD_INPUT_HANDLE)
                                     : i == 1 ? ::GetStdHandle(STD_OUTPUT_HANDLE)
                                              : ::GetStdHandle(STD_ERROR_HANDLE);
                    if (cur && cur != INVALID_HANDLE_VALUE)
                        std_dups[i] = dup_inheritable(cur);
                    else
                        // a windowed host has no std handles to give; the child
                        // gets the NUL device rather than a failed spawn -- an
                        // absent console is a normal situation, not a policy
                        // failure.
                        std_dups[i] = open_nul(true);
                } else if (req_fd >= 0) {
                    // legacy integer form: treat as a raw handle value
                    std_dups[i] = dup_inheritable(reinterpret_cast<HANDLE>(
                        static_cast<intptr_t>(req_fd)));
                }
            }
            if (!std_dups[i]) {
                return std::unexpected(win_error("spawn: standard handle setup"));
            }
            child_std[i] = std_dups[i].get();
        }
    }

    // ── 5. attribute list ─────────────────────────────────────────────────
    //
    // mitigation policy + appcontainer + child-process policy + the handle
    // list, so only the three standard handles are inheritable and nothing
    // else in this process leaks into the guest.
    std::vector<BYTE> attr_buf;
    LPPROC_THREAD_ATTRIBUTE_LIST attr_list = nullptr;
    // the list lives INSIDE attr_buf (a plain byte vector), so cleanup is
    // DeleteProcThreadAttributeList only -- HeapFree here would be freeing
    // memory the vector owns, which is corruption, not a leak.
    struct attr_cleanup {
        LPPROC_THREAD_ATTRIBUTE_LIST l{nullptr};
        ~attr_cleanup() { if (l) ::DeleteProcThreadAttributeList(l); }
    } attr_guard;

    const DWORD attr_count = 1 /*mitigation*/ + (c.use_app_container ? 1 : 0)
                           + (c.disable_child_processes ? 1 : 0) + 1 /*handle list*/;
    SIZE_T asize = 0;
    ::InitializeProcThreadAttributeList(nullptr, attr_count, 0, &asize);
    attr_buf.assign(asize, 0);
    attr_list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attr_buf.data());
    if (!::InitializeProcThreadAttributeList(attr_list, attr_count, 0, &asize))
        return std::unexpected(win_error("spawn: InitializeProcThreadAttributeList"));
    attr_guard.l = attr_list;

    // mitigation policy, one 64-bit word for the classes a policy names.
    {
        DWORD64 policy = 0;
        if (c.disable_dynamic_code)
            policy |= PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
        if (c.disable_win32k)
            policy |= PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON;
        if (c.disable_extension_points)
            policy |= PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON;
        if (policy && !::UpdateProcThreadAttribute(
                attr_list, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                &policy, sizeof(policy), nullptr, nullptr))
            return std::unexpected(win_error("spawn: mitigation policy attribute"));
    }

    // the appcontainer itself: SID + capability list in one attribute.
    if (c.use_app_container) {
        SECURITY_CAPABILITIES sc{};
        sc.AppContainerSid = cc.profile_sid.get();
        sc.Capabilities = cc.caps.empty() ? nullptr : cc.caps.data();
        sc.CapabilityCount = static_cast<DWORD>(cc.caps.size());
        if (!::UpdateProcThreadAttribute(
                attr_list, 0, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                &sc, sizeof(sc), nullptr, nullptr))
            return std::unexpected(win_error("spawn: appcontainer attribute"));
    }

    // no children: a separate attribute rather than a mitigation-policy bit.
    if (c.disable_child_processes) {
        DWORD child_policy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
        if (!::UpdateProcThreadAttribute(
                attr_list, 0, PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
                &child_policy, sizeof(child_policy), nullptr, nullptr))
            return std::unexpected(win_error("spawn: child process policy attribute"));
    }

    // handle list: the ONLY handles the child inherits are the ones named
    // here. without it, every inheritable handle in this process would land
    // in the guest -- authorities the sandbox cannot see or revoke.
    {
        HANDLE inherit[3] = {child_std[0], child_std[1], child_std[2]};
        if (!::UpdateProcThreadAttribute(
                attr_list, 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                inherit, sizeof(inherit), nullptr, nullptr))
            return std::unexpected(win_error("spawn: handle list attribute"));
    }

    // ── 7. the token: restricted, so the read wall is real ─────────────
    //
    // the appcontainer attribute ALONE does not build a read wall: the
    // lowbox token keeps the user SID and every group, so any DACL that
    // grants the user read (which is all of their own files) grants the
    // container read too. measured here first: `type %USERPROFILE%\\.ssh\\...`
    // returned 0 from inside a caps-less container before this token
    // existed. what builds the read wall is the RESTRICTED list: access is
    // granted only if EITHER list grants it, and the restricted list carries
    // no user SID -- so the user's grants stop counting, the package SID's
    // (stamped above) start, and BUILTIN\\Users keeps the toolchain readable.
    //
    // gated on the probe's VERDICT, not on the API's existence: several
    // insider builds accept CreateRestrictedToken and then kill every child
    // during ntdll init. a host that fails the probe gets the honest weaker
    // sandbox (appcontainer default-deny) rather than one that cannot start
    // a child at all.
    handle_guard restricted;
    if (c.restricted_tokens_ok) {
        HANDLE base = nullptr;
        if (!::OpenProcessToken(::GetCurrentProcess(),
                                TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
                                &base))
            return std::unexpected(win_error("spawn: OpenProcessToken"));
        handle_guard base_guard{base};

        // restricted list = BUILTIN\Users + Everyone, WELL-KNOWN SIDs ONLY.
        // the kernel rejects a restricted list containing appcontainer-namespace
        // SIDs outright (ERROR_INVALID_PARAMETER, measured: package-only and
        // package+users both fail with 87) -- those S-1-15-* SIDs identify a
        // package, and a restricted list is a set of ACCOUNT sids. what the
        // list does instead is subtract: access requires BOTH the normal list
        // and this one to grant, and neither Users nor Everyone grants read on
        // the user's own files, so the user-SID grants stop counting -- the
        // read wall -- while the toolchain under C:\Windows stays readable via
        // its Users:(RX) ACE.
        std::vector<SID_AND_ATTRIBUTES> restricted_list;
        std::vector<BYTE> sid_storage;
        for (const WELL_KNOWN_SID_TYPE type : {WinBuiltinUsersSid, WinWorldSid}) {
            BYTE sid_buf[SECURITY_MAX_SID_SIZE]{};
            DWORD sid_size = sizeof(sid_buf);
            if (!::CreateWellKnownSid(type, nullptr, sid_buf, &sid_size)) continue;
            const size_t off = sid_storage.size();
            sid_storage.resize(off + sid_size);
            std::memcpy(sid_storage.data() + off, sid_buf, sid_size);
        }
        // pointers AFTER the storage is final (vector reallocation would
        // invalidate earlier ones -- see make_container for the same rule).
        size_t off = 0;
        while (off < sid_storage.size()) {
            SID_AND_ATTRIBUTES a{};
            a.Sid = sid_storage.data() + off;
            // the restricted list ignores Attributes; SE_GROUP_ENABLED is
            // group-list vocabulary, and a nonzero value here is exactly the
            // kind of ERROR_INVALID_PARAMETER CreateRestrictedToken fails
            // with -- measured, not guessed.
            a.Attributes = 0;
            restricted_list.push_back(a);
            off += ::GetSidLengthRequired(
                static_cast<UCHAR>(*::GetSidSubAuthorityCount(
                    reinterpret_cast<PSID>(sid_storage.data() + off))));
        }
        if (restricted_list.empty()) {
            // no well-known SID derivable (should not happen on windows); the
            // read wall is unbuildable, degrade to appcontainer-only.
            c.restricted_tokens_ok = false;
        }

        HANDLE tok = nullptr;
        if (!::CreateRestrictedToken(base, 0, 0, nullptr,
                                     0, nullptr,  // drop NOTHING here; privileges
                                                  // go below
                                     static_cast<DWORD>(restricted_list.size()),
                                     restricted_list.empty() ? nullptr
                                                             : restricted_list.data(),
                                     &tok))
            return std::unexpected(win_error("spawn: CreateRestrictedToken"));
        restricted = handle_guard{tok};

        // drop every privilege the base token holds. a sandboxed compiler
        // needs none; SeShutdownPrivilege et al. surviving the wall is a
        // privilege a policy never asked for.
        DWORD len = 0;
        ::GetTokenInformation(tok, TokenPrivileges, nullptr, 0, &len);
        if (len) {
            std::vector<BYTE> pb(len);
            auto* privs = reinterpret_cast<PTOKEN_PRIVILEGES>(pb.data());
            if (::GetTokenInformation(tok, TokenPrivileges, privs, len, &len) &&
                privs->PrivilegeCount > 0) {
                // CreateRestrictedToken(0 privileges-to-delete) keeps them;
                // AdjustTokenPrivileges on the new token removes all.
                ::AdjustTokenPrivileges(tok, TRUE, nullptr, 0, nullptr, nullptr);
            }
        }
    }

    // ── 8. command line + environment ─────────────────────────────────
    // argv[0] is the program NAME (the posix convention all three backends
    // share); the command line is the program followed by argv[1..]. pushing
    // argv[0] as well would run `prog prog arg` on every call.
    std::string cmdline = quote_arg(req.program);
    for (const char* const* a = req.argv; *a; ++a) {
        if (a == req.argv) continue;  // argv[0]: the name, already in front
        cmdline += " ";
        cmdline += quote_arg(*a);
    }
    const std::wstring wcmdline = widen(cmdline);
    const std::wstring wworkdir = req.workdir.empty() ? std::wstring{} : widen(req.workdir);

    std::vector<wchar_t> env_block = build_env_block(req.envp);

    // ── 7. create, confined before the first instruction ──────────────────
    STARTUPINFOEXW si{};
    si.StartupInfo.cb         = sizeof(si);
    si.StartupInfo.dwFlags    = STARTF_USESTDHANDLES;
    si.StartupInfo.hStdInput  = child_std[0];
    si.StartupInfo.hStdOutput = child_std[1];
    si.StartupInfo.hStdError  = child_std[2];

    DWORD flags = CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT |
                  CREATE_UNICODE_ENVIRONMENT | CREATE_NO_WINDOW;
    PROCESS_INFORMATION pi{};
    // the restricted token is the primary token when the host passed the
    // probe: the child runs with the restricted list from its first
    // instruction, same rule as the posix backends' post-fork seccomp
    // install -- the wall is up before the program can act on anything.
    // without it (probe said no), plain CreateProcessW carries the
    // appcontainer attribute, which is the wall that still holds.
    const BOOL created =
        restricted
            ? ::CreateProcessAsUserW(restricted.get(), nullptr,
                                     const_cast<LPWSTR>(wcmdline.c_str()),
                                     nullptr, nullptr, TRUE, flags,
                                     env_block.empty() ? nullptr : env_block.data(),
                                     wworkdir.empty() ? nullptr : wworkdir.c_str(),
                                     &si.StartupInfo, &pi)
            : ::CreateProcessW(nullptr,
                               const_cast<LPWSTR>(wcmdline.c_str()),
                               nullptr, nullptr, TRUE, flags,
                               env_block.empty() ? nullptr : env_block.data(),
                               wworkdir.empty() ? nullptr : wworkdir.c_str(),
                               &si.StartupInfo, &pi);
    // env-gated trace (CLAYBIN_TRACE=1): the 0xc0000142 isolation work needs
    // the real decision facts per spawn, without a rebuild of the consumer.
    // stderr, one line, after the call so the verdict rides along.
    const bool trace = [] {
        char b[8]{};
        const DWORD n = ::GetEnvironmentVariableA("CLAYBIN_TRACE", b, sizeof b);
        return n > 0 && n < sizeof b && b[0] == '1';
    }();
    if (trace)
        std::fprintf(stderr, "[claybin] spawn: api=%s ac=%d rt_compiled=%d rt_used=%d caps=%zu "
                     "mem=%llu procs=%u wx=%d extpts=%d childpol=%d "
                     "workdir='%s' env=%zu flags=0x%lx created=%d\n",
                     restricted ? "AsUser" : "W",
                     c.use_app_container, c.restricted_tokens_ok,
                     static_cast<int>(static_cast<bool>(restricted)),
                     cc.caps.size(),
                     static_cast<unsigned long long>(c.memory_limit_bytes),
                     c.active_process_limit,
                     static_cast<int>(c.disable_dynamic_code),
                     static_cast<int>(c.disable_extension_points),
                     static_cast<int>(c.disable_child_processes),
                     req.workdir.c_str(),
                     env_block.size(),
                     static_cast<unsigned long>(flags),
                     static_cast<int>(created));
    if (!created) {
        return std::unexpected(win_error(restricted ? "spawn: CreateProcessAsUserW"
                                                    : "spawn: CreateProcessW"));
    }

    // ── 8. into the job BEFORE it runs, then go ───────────────────────────
    if (!::AssignProcessToJobObject(job.get(), pi.hProcess)) {
        const Error e = win_error("spawn: AssignProcessToJobObject");
        ::TerminateProcess(pi.hProcess, 1);
        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
        return std::unexpected(e);
    }
    ::ResumeThread(pi.hThread);
    ::CloseHandle(pi.hThread);
    // BOTH handles go to the caller: the process handle is the waitable exit
    // and the reap source, the job is the kill switch and the limit boundary.
    out.pid     = static_cast<int>(pi.dwProcessId);
    out.process = pi.hProcess;
    out.job     = job.release();  // ownership moved to the caller
    return out;
}

// the public entry point: first call probes for real, every later call in
// this process gets that answer. see the block comment above.
HostCapabilities probe_host() { return cached_host_probe(); }

}  // namespace clay::windows

#else  // !_WIN32

namespace clay::windows {
HostCapabilities probe_host() { return HostCapabilities::none(); }
}  // namespace clay::windows

#endif  // _WIN32
