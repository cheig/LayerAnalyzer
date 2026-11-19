// Copyright (c) 2026 cheig; GPL-3.0.
// This lwIP instance belongs exclusively to the HEV worker. Run only after its
// tasks and gateway have stopped, while the worker's allocator is still alive.
#include "lwip/opt.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/udp.h"
#include "lwip/ip4_frag.h"
#include "lwip/ip6_frag.h"

int layeranalyzer_lwip_tcp_count(void)
{
    int count = 0;
    unsigned int i;
    for (i = 0; i < NUM_TCP_PCB_LISTS; ++i) {
        const struct tcp_pcb *pcb;
        for (pcb = *tcp_pcb_lists[i]; pcb; pcb = pcb->next)
            ++count;
    }
    return count;
}

int layeranalyzer_lwip_udp_count(void)
{
    int count = 0;
    const struct udp_pcb *pcb;
    for (pcb = udp_pcbs; pcb; pcb = pcb->next)
        ++count;
    return count;
}

void layeranalyzer_lwip_release_run(void)
{
    // Closing HEV's listener does not discard incomplete handshakes or TIME_WAIT
    // PCBs. tcp_init() does not clear these lists, but the next memp_init() resets
    // their storage. Release them before either the allocator or pools are reset.
    while (tcp_listen_pcbs.pcbs)
        tcp_close(tcp_listen_pcbs.pcbs);
    while (tcp_active_pcbs) {
        tcp_arg(tcp_active_pcbs, NULL);
        tcp_err(tcp_active_pcbs, NULL);
        tcp_abandon(tcp_active_pcbs, 0);
    }
    while (tcp_bound_pcbs) {
        tcp_arg(tcp_bound_pcbs, NULL);
        tcp_err(tcp_bound_pcbs, NULL);
        tcp_abandon(tcp_bound_pcbs, 0);
    }
    while (tcp_tw_pcbs)
        tcp_abandon(tcp_tw_pcbs, 0);
    while (udp_pcbs)
        udp_remove(udp_pcbs);

    // Fragment queues can also retain pool pbufs across runs. Expire them before
    // HEV destroys this thread's allocator; no gateway/netif remains to emit ICMP.
#if LWIP_IPV4 && IP_REASSEMBLY
    for (unsigned int i = 0; i <= IP_REASS_MAXAGE; ++i)
        ip_reass_tmr();
#endif
#if LWIP_IPV6 && LWIP_IPV6_REASS
    for (unsigned int i = 0; i <= IPV6_REASS_MAXAGE; ++i)
        ip6_reass_tmr();
#endif
}
