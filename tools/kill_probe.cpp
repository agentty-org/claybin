// kill_probe — measures, on THIS host, how a sandboxed (appcontainer) child
// dies when we ask it to:
//
//   phase 1  spawn `ping -n 21` (a grandchild of cmd) under the appcontainer,
//            adopt it into jaal's windows_process, watch the exit, and at
//            ~300 ms call stop(graceful, tree). jaal's windows backend maps
//            graceful to TerminateProcess on the LEADER (adopted processes
//            carry no job handle), so the question is: does the leader die,
//            how fast does the exit fire, and does ping outlive it?
//   phase 2  same spawn, but TerminateJobObject via claybin's job handle —
//            the kill_tree() hook the exec loop falls back to.
//
// Build (MSYS2 clang64, from the claybin root):
//   clang++ -std=c++23 -O1 -Iinclude -I../maya/third_party/jaal/include
//       tools/kill_probe.cpp src/windows/spawn.cpp
//       ../maya/third_party/jaal/src/platform/windows/{process,wait_reactor,handle}.cpp
//       -o build/kill_probe.exe -luserenv -lwinmm
#include <cstdio>
#include <chrono>
#include <string>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <userenv.h>

#include <jaal/platform/windows/process.hpp>
#include <jaal/platform/windows/wait_reactor.hpp>

#include <claybin/windows/backend.hpp>
#include <claybin/policy/shapes.hpp>

using namespace clay;
using clk = std::chrono::steady_clock;
static clk::time_point t0;

static long long ms_since(clk::time_point t) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(clk::now() - t).count();
}

int main() {
    namespace pf = ::jaal::platform;
    const auto host = windows::probe_host();
    std::printf("probe: ac=%d rt=%d mit=%d\n", host.app_container,
                host.restricted_tokens, host.mitigation_policies);

    for (int phase = 1; phase <= 2; ++phase) {
        auto pol = Policy<Draft>{}
                       .read("C:\\Windows")
                       .execute("C:\\Windows\\System32")
                       .read_write("C:\\_Workspace_\\claybin\\build")
                       .allow_fork()
                       .allow_exec()
                       .connect("", 0)
                       .seal();
        windows::Options opts;
        opts.profile_name = "claybin.killprobe";
        opts.allow_host_acl_mutation = true;
        auto c = windows::compile(pol, host, opts);
        if (!c) {
            const std::string m{c.error().mechanism};
            std::printf("compile failed: %s\n", m.c_str());
            return 1;
        }

        SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
        HANDLE r = nullptr, w = nullptr;
        if (!::CreatePipe(&r, &w, &sa, 0)) return 1;

        const char* argv[] = {"cmd.exe", "/d", "/s", "/c",
                              "ping -n 21 127.0.0.1 >nul& echo done", nullptr};
        windows::SpawnRequest req;
        req.program   = "cmd.exe";
        req.argv      = argv;
        req.stdout_fd = static_cast<int>(reinterpret_cast<intptr_t>(w));
        req.stderr_fd = static_cast<int>(reinterpret_cast<intptr_t>(w));
        req.workdir   = "C:\\_Workspace_\\claybin\\build";
        auto s = windows::spawn(*c, req);
        ::CloseHandle(w);
        if (!s) { std::printf("spawn failed\n"); return 1; }
        const HANDLE job = static_cast<HANDLE>(s->job);
        const auto t_start = clk::now();

        pf::windows_process::adopted_child a;
        a.pid         = static_cast<int>(s->pid);
        a.process     = s->process;               // ownership moves
        s->process    = nullptr;
        a.stdout_pipe = r;                        // read end moves too
        auto p = pf::windows_process::adopt(std::move(a));
        if (!p) { std::printf("adopt failed\n"); return 1; }

        auto reactor = pf::wait_reactor::create();
        auto exit_reg = reactor->watch(p->exit_handle().get(), pf::interest::read, 1);
        const HANDLE out_h = static_cast<HANDLE>(p->stdout_handle()->get());
        auto out_reg  = reactor->watch(out_h, pf::interest::read, 2);

        const auto kill_at = t_start + std::chrono::milliseconds{300};
        bool killed = false, exited = false;
        long long exit_ms = -1;
        char buf[4096];
        std::string out;

        for (;;) {
            const auto now = clk::now();
            auto next = now + std::chrono::hours{24};
            if (!killed) next = std::min(next, kill_at);
            const auto wait_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                next > now ? next - now : std::chrono::milliseconds::zero());
            auto res = reactor->wait(wait_ms);
            const auto woke = clk::now();
            std::printf("  [%lldms] wait returned after %lldms events=%u timeout=%d\n",
                        ms_since(t_start),
                        std::chrono::duration_cast<std::chrono::milliseconds>(woke - now).count(),
                        res ? res->count : 0u, res ? res->timeout : 0);
            if (res) {
                for (std::uint8_t i = 0; i < res->count; ++i) {
                    const auto& e = res->ready[i];
                    if (e.token == 1) {
                        exited = true;
                        exit_ms = ms_since(t_start);
                    } else if (e.token == 2) {
                        bool eof = false;
                        const auto n = pf::read_some(p->stdout_handle().value(), buf, sizeof buf, eof);
                        if (n > 0) out.append(buf, n);
                        std::printf("  [%lldms] stdout %zu bytes eof=%d\n",
                                    ms_since(t_start), n, eof);
                    }
                }
            }
            if (exited) break;
            const auto t = clk::now();
            if (!killed && t >= kill_at) {
                killed = true;
                if (phase == 1) {
                    std::printf("  [%lldms] graceful stop (TerminateProcess on leader)\n",
                                ms_since(t_start));
                    const auto st = p->stop(pf::stop_mode::graceful, pf::stop_scope::tree);
                    std::printf("  [%lldms] graceful returned ok=%d\n",
                                ms_since(t_start), static_cast<int>(static_cast<bool>(st)));
                } else {
                    std::printf("  [%lldms] TerminateJobObject\n", ms_since(t_start));
                    ::TerminateJobObject(job, 1);
                }
                continue;
            }
            if (killed && t >= kill_at + std::chrono::seconds{8}) {
                std::printf("  [%lldms] GIVING UP: exit never fired 8s after the kill\n",
                            ms_since(t_start));
                break;
            }
        }
        std::printf("phase %d: exit fired at %lldms output='%s' (expected: kill lands ~300ms,\n"
                    "         ping's natural end would be ~20000ms)\n\n",
                    phase, exit_ms, out.c_str());
        (void)p->reap();
        ::CloseHandle(job);
        ::DeleteAppContainerProfile(L"claybin.killprobe");
    }
    return 0;
}
