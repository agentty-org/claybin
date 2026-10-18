// prints the full HostCapabilities verdict on this host, one line per field.
#include <cstdio>
#include "claybin/windows/backend.hpp"

int main() {
    for (int round = 1; round <= 3; ++round) {
        const auto h = clay::windows::probe_host();
        std::printf("round %d: ac=%d rt=%d mit=%d\n", round,
                    h.app_container, h.restricted_tokens, h.mitigation_policies);
    }
    return 0;
}
