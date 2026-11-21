// claybin: the mount model -- constructing a filesystem tree, bubblewrap-style.
//
// this is a DIFFERENT axis from FsAuthority, and claybin does both:
//
//   mounts    decide what is VISIBLE at all (a new root built from binds)
//   landlock  decide what is ACCESSIBLE among the things that are visible
//
// bubblewrap only has the first. a path that is bind-mounted read-write into a
// bwrap sandbox is fully writable, and the only way to narrow it is to not mount
// it. claybin can mount a tree and then further restrict it, so "mount
// /workspace rw but deny .git" is expressible without a second bind.
//
// the two also fail differently, which is the point of having both: a mount
// mistake makes a path invisible, a landlock mistake makes it inaccessible, and
// an attacker needs to beat both.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>
#if !defined(_WIN32)
#include <unistd.h>
#endif

#include "claybin/core/fd.hpp"
#include "claybin/core/lattice.hpp"
#include "claybin/policy/filesystem.hpp"

namespace clay {

// is `link` already a symlink on THIS host pointing at exactly `target`? the
// question a mountless backend asks of a symlink in the plan: if the answer is
// yes, the tree it would have built is the tree that exists, and access
// control over the real path stands in faithfully. readlink, not stat: a link
// to the right place through a different spelling is a different link.
inline bool host_symlink_matches(const std::string& link, const std::string& target) {
#if defined(_WIN32)
    (void)link;
    (void)target;
    return false;
#else
    char buf[4096];
    const ssize_t n = ::readlink(link.c_str(), buf, sizeof buf);
    if (n <= 0 || static_cast<std::size_t>(n) >= sizeof buf) return false;
    return std::string_view{buf, static_cast<std::size_t>(n)} == target;
#endif
}

enum class MountKind : std::uint8_t {
    bind,      // bind a host path in, read-write
    bind_ro,   // bind a host path in, read-only
    bind_dev,  // bind allowing device nodes (--dev-bind)
    tmpfs,     // fresh empty tmpfs
    proc,      // a new procfs, showing only this pid namespace
    devtmpfs,  // a minimal /dev: null, zero, full, random, urandom, tty
    mqueue,
    symlink,   // a symlink, not a mount, but part of tree construction
    dir,       // mkdir

    // make a path be NOTHING, whatever the tree around it says.
    //
    // this is the only sound way to express "everything under here except
    // that". landlock cannot: landlock_add_rule() with allowed_access == 0 is
    // rejected with ENOMSG (measured, abi 10), and omitting a rule means the
    // path INHERITS its ancestor's grant, because resolution takes the most
    // specific rule that exists. so a deny under a grant has no landlock
    // spelling at all -- I wrote one, watched it reach the plan, and read the
    // file anyway.
    //
    // what works is making the path not be the file: an empty tmpfs over a
    // directory, an empty read-only file over a file. the guest sees an empty
    // ~/.aws rather than a denied one, which is also the better failure mode --
    // a tool reading it gets no credentials instead of an EACCES it may report
    // as a bug.
    //
    // apply() stats the target to pick which, because a plan may be applied on
    // a machine where the path is a different kind of thing than it was here.
    mask,

    // overlayfs. `sources` holds the lower layers, lowest-priority LAST --
    // which is overlayfs's own convention and the opposite of intuition, so it
    // is worth stating twice.
    //
    //   overlay     writable upper layer at `source`, work dir at `workdir`
    //   tmp_overlay writable upper layer on a fresh tmpfs, so changes vanish
    //   ro_overlay  no upper layer at all; needs >= 2 lowers to be meaningful
    overlay,
    tmp_overlay,
    ro_overlay,

    // content read from a descriptor the caller holds.
    //
    //   file       write the bytes to a plain file inside the tree
    //   bind_data  write them to a temp file, bind it in, then UNLINK it, so
    //              the backing file has no name the guest could ever open
    file,
    bind_data,
    bind_data_ro,
};

constexpr const char* to_string(MountKind k) {
    switch (k) {
        case MountKind::bind: return "bind";
        case MountKind::bind_ro: return "bind-ro";
        case MountKind::bind_dev: return "dev-bind";
        case MountKind::tmpfs: return "tmpfs";
        case MountKind::proc: return "proc";
        case MountKind::devtmpfs: return "dev";
        case MountKind::mqueue: return "mqueue";
        case MountKind::symlink: return "symlink";
        case MountKind::mask: return "mask";
        case MountKind::dir: return "dir";
        case MountKind::overlay: return "overlay";
        case MountKind::tmp_overlay: return "tmp-overlay";
        case MountKind::ro_overlay: return "ro-overlay";
        case MountKind::file: return "file";
        case MountKind::bind_data: return "bind-data";
        case MountKind::bind_data_ro: return "ro-bind-data";
    }
    return "?";
}

// ---------------------------------------------------------------------------
// two interpretations
//
// a MountPlan is a FREE structure: an ordered sequence, with concatenation as
// its only composition. it is deliberately not a lattice, because two trees do
// not intersect in any meaningful way.
//
// what makes it portable is that it admits TWO interpretations (two folds):
//
//   to_tree(plan)       a filesystem construction    -- linux only
//   to_authority(plan)  an FsAuthority               -- everywhere
//
// on linux we run both, and they check each other. on a host with no mount
// namespaces only the second exists, and the question becomes: is the second
// interpretation FAITHFUL to the first? that depends on the plan, and it is
// decidable by looking at it.
//
// the deciding property is REMAPPING. `--ro-bind /usr /usr` says "this path
// keeps its name", which an access-control backend can express exactly. but
// `--ro-bind /opt/app /app` says "this path gets a NEW name", and no amount of
// access control can rename a path. that is a mount-only capability.
//
// so fidelity is a property of the plan, computed once, and reported rather
// than discovered at runtime on a user's machine.
// ---------------------------------------------------------------------------

enum class Fidelity : std::uint8_t {
    // the access interpretation is EXACTLY the tree interpretation. every bind
    // keeps its path, so "restrict to these subtrees" says the same thing as
    // "build a tree from these subtrees". portable with full strength.
    exact = 2,

    // the access interpretation is a sound but weaker approximation. a tmpfs
    // becomes "you may write here", losing the guarantees that it starts empty
    // and is size-capped. nothing is granted that the tree would not have
    // shown, so it is safe -- just less.
    approximate = 1,

    // no access-control interpretation exists. the plan renames paths or
    // synthesizes entries, and neither is expressible without a real tree.
    // a backend without mounts must REFUSE rather than pretend.
    impossible = 0,
};

constexpr const char* to_string(Fidelity f) {
    switch (f) {
        case Fidelity::exact: return "exact";
        case Fidelity::approximate: return "approximate";
        case Fidelity::impossible: return "impossible";
    }
    return "?";
}

// fidelity is a meet: a plan is only as faithful as its least faithful mount.
constexpr Fidelity meet(Fidelity a, Fidelity b) { return a < b ? a : b; }

// why a particular mount limits the plan's fidelity, for an error message that
// names the offending line rather than saying "unsupported".
struct FidelityNote {
    std::size_t index{0};
    Fidelity fidelity{Fidelity::exact};
    const char* reason{""};
};

struct Mount {
    MountKind kind{MountKind::bind_ro};
    std::string source;  // host path, or symlink target; empty for tmpfs/proc
    std::string dest;    // path inside the sandbox
    std::uint64_t size{0};      // tmpfs size limit, 0 = default
    std::uint32_t perms{0};     // octal mode for dir/tmpfs/file, 0 = default
    bool optional{false};       // --bind-try: skip if source is missing

    // overlay only. `lowers` are the read-only layers, HIGHEST priority first
    // (overlayfs's own order); `workdir` is the scratch directory overlayfs
    // needs on the same filesystem as the upper layer.
    std::vector<std::string> lowers{};
    std::string workdir{};

    // for file/bind_data: the descriptor whose CONTENTS go at `dest`. borrowed,
    // never closed by us -- the caller owns it. -1 when unused.
    int content_fd{-1};

    friend bool operator==(const Mount&, const Mount&) = default;
};

// an ordered list. unlike the other policy components this is NOT a lattice:
// mount order is semantically significant (you must create /usr before binding
// /usr/local under it), so it is a sequence, not a set.
//
// that means composition cannot be meet. two mount plans do not intersect in
// any meaningful way -- "the tree you get from both" is not well defined. so
// composing policies keeps the mounts of whichever side has them and rejects
// the combination if both do, rather than silently producing a tree neither
// caller asked for.
class MountPlan {
  public:
    MountPlan() = default;

    MountPlan& bind(std::string src, std::string dst) {
        mounts_.push_back({MountKind::bind, std::move(src), std::move(dst), 0, 0, false, {}, {}});
        return *this;
    }
    MountPlan& bind_ro(std::string src, std::string dst) {
        mounts_.push_back({MountKind::bind_ro, std::move(src), std::move(dst), 0, 0, false, {}, {}});
        return *this;
    }
    MountPlan& bind_try(std::string src, std::string dst, bool ro = true) {
        mounts_.push_back({ro ? MountKind::bind_ro : MountKind::bind, std::move(src),
                           std::move(dst), 0, 0, true, {}, {}});
        return *this;
    }
    MountPlan& dev_bind(std::string src, std::string dst) {
        mounts_.push_back({MountKind::bind_dev, std::move(src), std::move(dst), 0, 0, false, {}, {}});
        return *this;
    }
    // perms 0 means the default, 0755 -- bwrap's historical tmpfs mode.
    MountPlan& tmpfs(std::string dst, std::uint64_t size = 0, std::uint32_t perms = 0) {
        mounts_.push_back({MountKind::tmpfs, {}, std::move(dst), size, perms, false, {}, {}});
        return *this;
    }
    MountPlan& proc(std::string dst = "/proc") {
        mounts_.push_back({MountKind::proc, {}, std::move(dst), 0, 0, false, {}, {}});
        return *this;
    }
    MountPlan& dev(std::string dst = "/dev") {
        mounts_.push_back({MountKind::devtmpfs, {}, std::move(dst), 0, 0, false, {}, {}});
        return *this;
    }

    // make `dst` be nothing: an empty directory or an empty read-only file,
    // whichever it already is. see MountKind::mask for why this is a mount and
    // not a landlock rule.
    //
    // optional by default, because the usual caller is masking a list of
    // credential paths and a user who has no ~/.aws should not fail to start.
    MountPlan& mask(std::string dst, bool optional = true) {
        mounts_.push_back(
            {MountKind::mask, {}, std::move(dst), 0, 0, optional, {}, {}});
        return *this;
    }
    MountPlan& mqueue(std::string dst = "/dev/mqueue") {
        mounts_.push_back({MountKind::mqueue, {}, std::move(dst), 0, 0, false, {}, {}});
        return *this;
    }
    MountPlan& symlink(std::string target, std::string dst) {
        mounts_.push_back({MountKind::symlink, std::move(target), std::move(dst), 0, 0, false, {}, {}});
        return *this;
    }
    MountPlan& dir(std::string dst, std::uint32_t perms = 0755) {
        mounts_.push_back({MountKind::dir, {}, std::move(dst), 0, perms, false, {}, {}});
        return *this;
    }

    // ---- overlays --------------------------------------------------------
    //
    // bubblewrap spells these as a stateful pair: `--overlay-src A --overlay-src
    // B --overlay UPPER WORK DEST`, where the src flags accumulate and the
    // terminator consumes them. that is easy to get wrong -- an --overlay with
    // no preceding --overlay-src is an error bwrap only catches at runtime.
    //
    // here the layers are a REQUIRED ARGUMENT instead, so "an overlay with no
    // lower layers" is not a state you can reach. the CLI still accepts bwrap's
    // spelling and accumulates into a vector before calling these.

    // a writable overlay: `upper` receives all changes, `work` is overlayfs's
    // scratch dir (must be on the same filesystem as upper), `lowers` are the
    // read-only layers with HIGHEST priority first.
    MountPlan& overlay(std::vector<std::string> lowers, std::string upper,
                       std::string work, std::string dst) {
        mounts_.push_back({MountKind::overlay, std::move(upper), std::move(dst), 0, 0, false,
                           std::move(lowers), std::move(work)});
        return *this;
    }

    // a writable overlay whose upper layer is a fresh tmpfs: the guest can write
    // anywhere in the tree and every change is discarded when the sandbox exits.
    // this is the interesting one for running untrusted builds against a real
    // source tree.
    MountPlan& tmp_overlay(std::vector<std::string> lowers, std::string dst) {
        mounts_.push_back({MountKind::tmp_overlay, {}, std::move(dst), 0, 0, false,
                           std::move(lowers), {}});
        return *this;
    }

    // a read-only overlay: no upper layer, so the merged view cannot be written
    // at all. needs at least two lowers to be worth doing.
    MountPlan& ro_overlay(std::vector<std::string> lowers, std::string dst) {
        mounts_.push_back({MountKind::ro_overlay, {}, std::move(dst), 0, 0, false,
                           std::move(lowers), {}});
        return *this;
    }

    // ---- descriptors as sources ------------------------------------------
    //
    // an fd names an OBJECT, not a path, so binding one is immune to every
    // symlink and TOCTOU race that path resolution suffers from -- in principle.
    // in practice see bind_fd below: the kernel will not let us mount a
    // descriptor that came from another mount namespace, which a caller's fd
    // always has, so these resolve to a path and inherit its races. the property
    // is real for `file`/`bind_data`, which READ the fd rather than mount it.

    // bind whatever `fd` refers to.
    //
    // the fd is resolved to its real path via readlink(/proc/self/fd/N) HERE,
    // pre-fork, and the path is what gets bound.
    //
    // that is weaker than binding the descriptor, and the reason is NOT the one
    // this comment used to give. it claimed the kernel refuses to bind through a
    // magic symlink -- it does not. mount("/proc/self/fd/N", MS_BIND) succeeds,
    // and it follows the object rather than the name, which would be exactly
    // what we want. the real obstacle is narrower and was only found by trying
    // it: the bind works only for a descriptor opened in the SAME mount
    // namespace. measured on 7.2, the identical call returns EINVAL for an fd
    // opened before unshare(CLONE_NEWNS) and succeeds for one opened after.
    // a caller's fd is always the former, so the approach cannot apply.
    //
    // open_tree(fd, OPEN_TREE_CLONE|AT_EMPTY_PATH) + move_mount() DOES bind a
    // descriptor without naming any path, and I recorded it here as a way to
    // close the window properly. having actually tried it: it cannot work, and
    // the reason is the same restriction wearing a different hat.
    //
    // OPEN_TREE_CLONE is scoped to the mount namespace the descriptor belongs
    // to, and needs CAP_SYS_ADMIN over it. measured, all three orderings:
    //   - in the parent, pre-fork: EPERM. we are unprivileged there.
    //   - in the child after unshare(CLONE_NEWUSER|CLONE_NEWNS): EINVAL on the
    //     caller's fd, ok on an fd opened in the child. the same cross-namespace
    //     rule as the magic symlink.
    //   - userns first (to gain caps), clone while still in the original mount
    //     namespace, then unshare(CLONE_NEWNS): still EPERM. an unprivileged
    //     userns does not OWN the parent mount namespace, so caps in it do not
    //     reach that namespace's mounts.
    //
    // a descriptor handed in from outside can therefore never be cloned by us,
    // whichever order we unshare in. this is a kernel-design boundary, not a
    // missing flag: it is what stops an unprivileged process from lifting mounts
    // out of a namespace it does not control.
    //
    // so: a TOCTOU window between resolution and mount remains, and it is not
    // closable from inside claybin. bubblewrap has it too and documents it. it is
    // narrower here because resolution happens pre-fork in the parent, capturing
    // the caller's own view of the filesystem -- but it is a window, and a caller
    // passing an fd into a directory somebody else can rename should know that.
    // verified: with the swap done after seal() and before spawn(), the guest
    // sees the replacement.
    //
    // what a caller CAN do about it: bind a path they control, or keep the fd's
    // directory somewhere no other writer can rename. mount_test pins the kernel
    // rules above so the day one of them changes, we find out.
    MountPlan& bind_fd(BorrowedFd fd, std::string dst, bool ro = false) {
        Mount m{};
        m.kind = ro ? MountKind::bind_ro : MountKind::bind;
        m.source = resolve_fd(fd);
        m.dest = std::move(dst);
        m.content_fd = fd.get();
        // a descriptor we could not resolve names nothing we can bind. mark it
        // optional so the sandbox still starts, with the path simply absent,
        // rather than failing in a way that looks like a policy error.
        m.optional = m.source.empty();
        mounts_.push_back(std::move(m));
        return *this;
    }

    // write the fd's contents to a plain file inside the tree.
    MountPlan& file(BorrowedFd fd, std::string dst, std::uint32_t perms = 0644) {
        Mount m{};
        m.kind = MountKind::file;
        m.dest = std::move(dst);
        m.perms = perms;
        m.content_fd = fd.get();
        mounts_.push_back(std::move(m));
        return *this;
    }

    // write the fd's contents to a temp file, bind it in, then UNLINK the temp.
    // strictly stronger than `file`: the bytes are present at `dest` and the
    // backing file has no name anywhere, so there is no second path to it even
    // for a guest that escapes the tree.
    MountPlan& bind_data(BorrowedFd fd, std::string dst, bool ro = false,
                         std::uint32_t perms = 0644) {
        Mount m{};
        m.kind = ro ? MountKind::bind_data_ro : MountKind::bind_data;
        m.dest = std::move(dst);
        m.perms = perms;
        m.content_fd = fd.get();
        mounts_.push_back(std::move(m));
        return *this;
    }

    bool empty() const { return mounts_.empty(); }
    const std::vector<Mount>& mounts() const { return mounts_; }

    // how faithfully a mountless backend can implement this plan, and why.
    // computed as a fold, so adding a mount kind forces a decision here.
    Fidelity fidelity(std::vector<FidelityNote>* notes = nullptr) const {
        Fidelity acc = Fidelity::exact;
        for (std::size_t i = 0; i < mounts_.size(); ++i) {
            const Mount& m = mounts_[i];
            Fidelity f = Fidelity::exact;
            const char* why = "";

            switch (m.kind) {
                case MountKind::bind:
                case MountKind::bind_ro:
                case MountKind::bind_dev:
                    // the whole question, in one comparison. same path in and
                    // out means access control can say it; a rename cannot.
                    if (path::normalize(m.source) != path::normalize(m.dest)) {
                        f = Fidelity::impossible;
                        why = "bind remaps a path; access control cannot rename";
                    }
                    break;
                case MountKind::tmpfs:
                    f = Fidelity::approximate;
                    why = "tmpfs becomes a plain write grant: not empty, not size-capped";
                    break;
                case MountKind::proc:
                    f = Fidelity::approximate;
                    why = "procfs is linux-only; elsewhere there is simply no /proc";
                    break;
                case MountKind::devtmpfs:
                    f = Fidelity::approximate;
                    why = "device allowlist becomes a read grant on existing nodes";
                    break;
                case MountKind::mqueue:
                    f = Fidelity::approximate;
                    why = "posix mqueue is linux-only";
                    break;
                case MountKind::symlink:
                    // on a merged-/usr host `/bin -> usr/bin` is already there:
                    // the tree we would build and the tree that exists agree,
                    // so access control over the real path is a faithful
                    // stand-in. only a link that does NOT already exist with
                    // this target would have to be created, which access
                    // control cannot do.
                    if (host_symlink_matches(m.dest, m.source)) {
                        f = Fidelity::approximate;
                        why = "symlink already present on the host; access control covers its target";
                    } else {
                        f = Fidelity::impossible;
                        why = "creating a symlink would mutate the host filesystem";
                    }
                    break;
                case MountKind::mask:
                    // windows can do this one: an ACL denying the AppContainer
                    // SID on that object is exactly "make this path be nothing
                    // to you", and unlike the landlock case it composes with
                    // the grants around it.
                    f = Fidelity::approximate;
                    why = "masked by a deny ACE for the container SID, not an empty mount";
                    break;
                case MountKind::dir:
                    f = Fidelity::impossible;
                    why = "creating a directory would mutate the host filesystem";
                    break;

                case MountKind::overlay:
                case MountKind::tmp_overlay:
                case MountKind::ro_overlay:
                    // an overlay MERGES several directories into one view. that
                    // is a genuinely new namespace, not a restriction of an
                    // existing one, so access control cannot stand in for it at
                    // any fidelity: there is no single host path whose contents
                    // are the merged view.
                    f = Fidelity::impossible;
                    why = "overlayfs merges layers into a new view; access control "
                          "cannot synthesize one";
                    break;

                case MountKind::file:
                case MountKind::bind_data:
                case MountKind::bind_data_ro:
                    // materializing content at a path is creation, not
                    // restriction. there is nothing on the host at `dest` for
                    // access control to point at.
                    f = Fidelity::impossible;
                    why = "writing content into the tree requires a real filesystem";
                    break;
            }

            if (f != Fidelity::exact && notes) notes->push_back({i, f, why});
            acc = clay::meet(acc, f);
        }
        return acc;
    }

    // shorthand: can a backend with no mount namespaces run this at all?
    bool is_portable() const { return fidelity() != Fidelity::impossible; }

    // derive the landlock grants implied by this tree, so a caller who only
    // described mounts still gets the second wall for free. read-only binds
    // become read grants, read-write binds become write grants.
    //
    // this is the OTHER interpretation of the same value, and it is what makes
    // the design cross-platform: on linux it is a second, independent wall
    // layered over the real tree; on a host with no mount namespaces it is the
    // only wall, and `fidelity()` says how much was lost getting there.
    //
    // SOUNDNESS: this must never grant a path the tree would not have shown.
    // every grant is keyed on a mount's dest, so a path with no covering mount
    // gets nothing -- which is the property tests/mount_algebra_test.cpp
    // checks against random plans.
    FsAuthority implied_authority() const {
        // grants join, so their order doesn't matter and they go in as one
        // batch (an insert each was quadratic for a big plan). a mask REPLACES
        // whatever was granted at its path, so the masks are applied after,
        // each only if no later mount grants that exact path again --
        // the same result the in-order loop gave.
        std::vector<FsGrant> grants;
        grants.reserve(mounts_.size());
        std::vector<std::size_t> masks;
        auto grant = [&](const std::string& p, FileRights r) { grants.push_back({p, r}); };
        for (std::size_t i = 0; i < mounts_.size(); ++i) {
            const auto& m = mounts_[i];
            switch (m.kind) {
                case MountKind::bind_ro:
                    grant(m.dest, FileRights::exec());  // read + execute
                    break;
                case MountKind::bind:
                case MountKind::bind_dev:
                    grant(m.dest, FileRights::all());
                    break;
                case MountKind::tmpfs:
                    grant(m.dest, FileRights::write());
                    break;
                case MountKind::proc:
                case MountKind::devtmpfs:
                case MountKind::mqueue:
                    grant(m.dest, FileRights::write());
                    break;
                case MountKind::symlink:
                    // a symlink IS content from the guest's point of view: it has
                    // to be readable or `ls -l` on it fails with EPERM, which
                    // looks like a broken sandbox rather than a missing grant.
                    grant(m.dest, FileRights::read());
                    break;
                case MountKind::mask:
                    // the one mount kind that REMOVES authority. an empty thing
                    // is mounted over the path, so the tree itself no longer
                    // offers the content -- and the implied authority has to say
                    // so, or the landlock ruleset would still grant read on a
                    // path the mount just emptied. harmless either way (there is
                    // nothing left to read) but the report would overstate what
                    // the guest can reach, and the report is the product.
                    masks.push_back(i);
                    break;
                case MountKind::dir:
                    // a directory we created for the guest should be usable.
                    // read-only: a caller who wants to write there binds or
                    // tmpfs-mounts it instead.
                    grant(m.dest, FileRights::read());
                    break;

                case MountKind::overlay:
                case MountKind::tmp_overlay:
                    // the merged view is writable, because the upper layer is.
                    grant(m.dest, FileRights::all());
                    break;
                case MountKind::ro_overlay:
                    // no upper layer, so the merge cannot be written at all.
                    grant(m.dest, FileRights::exec());  // read + execute
                    break;

                case MountKind::file:
                case MountKind::bind_data:
                    grant(m.dest, FileRights::write());
                    break;
                case MountKind::bind_data_ro:
                    grant(m.dest, FileRights::read());
                    break;
            }
        }
        FsAuthority fs;
        if (masks.empty()) {
            fs.grant_all(std::move(grants));
        } else {
            // a grant at a mask's path that comes AFTER the mask re-joins onto
            // the denial, so it has to be applied after it too.
            std::unordered_map<std::string, std::size_t> last_mask;
            for (auto i : masks) last_mask[path::normalize(mounts_[i].dest)] = i;
            std::vector<FsGrant> early, late;
            std::size_t gi = 0;
            for (std::size_t i = 0; i < mounts_.size(); ++i) {
                if (mounts_[i].kind == MountKind::mask) continue;
                auto& g = grants[gi++];
                auto it = last_mask.find(path::normalize(g.path));
                (it != last_mask.end() && i > it->second ? late : early).push_back(std::move(g));
            }
            fs.grant_all(std::move(early));
            for (auto& [p, _] : last_mask) fs.deny(p);
            for (auto& g : late) fs.grant(g.path, g.rights);
        }
        fs.normalize();
        return fs;
    }

    friend bool operator==(const MountPlan&, const MountPlan&) = default;

  private:
    std::vector<Mount> mounts_;
};

}  // namespace clay
