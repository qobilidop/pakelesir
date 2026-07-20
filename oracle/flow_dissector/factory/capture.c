// Golden factory: load upstream bpf_flow.c (compiled ELF) with libbpf,
// populate its tail-call prog-array, and BPF_PROG_TEST_RUN the entry
// program over each corpus packet, decoding bpf_flow_keys into a
// GoldenFile v2 JSON on stdout (schema matches src/oracle/flow_dissector.rs:
// per-entry disposition "ok"/"drop", keys only when ok).
//
// Usage: capture <bpf_flow.o> <corpus.txt>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <sys/utsname.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>

// BPF_OK / BPF_DROP from the flow-dissector program (linux/pkt_cls.h
// values TC_ACT_OK / TC_ACT_SHOT).
#define RET_OK 0
#define RET_DROP 2

// Upstream bpf_flow.c's jmp_table has MAX_PROG entries whose values are
// the programs named flow_dissector_<index> (the PROG() macro expands
// the IP..VLAN index macros into the symbol name).
#define MAX_PROG 6

static int is_hex(char c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

// hex string -> bytes; returns length, or -1 on odd-length/invalid input.
static int unhex(const char *s, unsigned char *out, int cap) {
    int n = 0;
    while (s[0] && s[0] != '\n') {
        if (!is_hex(s[0]) || !is_hex(s[1])) return -1;
        if (n >= cap) return -1;
        unsigned v;
        sscanf(s, "%2x", &v);
        out[n++] = (unsigned char)v;
        s += 2;
    }
    return n;
}

static void hexcat(char *dst, const unsigned char *b, int n) {
    for (int i = 0; i < n; i++) sprintf(dst + i * 2, "%02x", b[i]);
    dst[n * 2] = 0;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <bpf_flow.o> <corpus.txt>\n", argv[0]); return 2; }

    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    if (!obj) { fprintf(stderr, "open %s failed\n", argv[1]); return 1; }
    if (bpf_object__load(obj)) { fprintf(stderr, "load failed (need privilege?)\n"); return 1; }

    struct bpf_map *jmp = bpf_object__find_map_by_name(obj, "jmp_table");
    if (!jmp) { fprintf(stderr, "no jmp_table map — pin drift?\n"); return 1; }
    for (uint32_t i = 0; i < MAX_PROG; i++) {
        char name[32];
        snprintf(name, sizeof name, "flow_dissector_%u", i);
        struct bpf_program *p = bpf_object__find_program_by_name(obj, name);
        if (!p) { fprintf(stderr, "missing program %s — pin drift?\n", name); return 1; }
        int fd = bpf_program__fd(p);
        if (bpf_map__update_elem(jmp, &i, sizeof i, &fd, sizeof fd, BPF_ANY)) {
            fprintf(stderr, "jmp_table[%u] update failed\n", i); return 1;
        }
    }
    struct bpf_program *entry = bpf_object__find_program_by_name(obj, "_dissect");
    if (!entry) { fprintf(stderr, "missing entry program _dissect — pin drift?\n"); return 1; }
    int prog_fd = bpf_program__fd(entry);

    struct utsname un; uname(&un);
    printf("{\n  \"kernel_version\": \"%s\",\n", un.release);
    printf("  \"keys_subset\": [\"nhoff\",\"thoff\",\"n_proto\",\"addr_proto\",\"ip_proto\","
           "\"sport\",\"dport\",\"ipv4_src\",\"ipv4_dst\",\"ipv6_src\",\"ipv6_dst\"],\n");
    printf("  \"entries\": [\n");

    FILE *cf = fopen(argv[2], "r");
    if (!cf) { perror("fopen corpus"); return 1; }
    char line[8192];
    int first = 1;
    while (fgets(line, sizeof line, cf)) {
        if (line[0] == '\n' || line[0] == '#' || line[0] == 0) continue;
        unsigned char pkt[2048];
        int plen = unhex(line, pkt, sizeof pkt);
        if (plen <= 0) { fprintf(stderr, "bad corpus line\n"); return 1; }

        unsigned char out[256]; memset(out, 0, sizeof out);
        LIBBPF_OPTS(bpf_test_run_opts, topts,
            .data_in = pkt, .data_size_in = (uint32_t)plen,
            .data_out = out, .data_size_out = sizeof out,
            .repeat = 1,
        );
        if (bpf_prog_test_run_opts(prog_fd, &topts)) {
            fprintf(stderr, "TEST_RUN failed\n"); return 1;
        }
        char phex[4200]; hexcat(phex, pkt, plen);
        if (topts.retval == RET_DROP) {
            printf("%s    {\"packet_hex\": \"%s\", \"disposition\": \"drop\"}",
                   first ? "" : ",\n", phex);
            first = 0;
            continue;
        }
        if (topts.retval != RET_OK) {
            fprintf(stderr, "unexpected retval %u (not BPF_OK/BPF_DROP)\n", topts.retval);
            return 1;
        }
        struct bpf_flow_keys *k = (struct bpf_flow_keys *)out;
        char v4s[9] = "", v4d[9] = "", v6s[33] = "", v6d[33] = "";
        if (ntohs(k->n_proto) == 0x0800) {
            hexcat(v4s, (unsigned char *)&k->ipv4_src, 4);
            hexcat(v4d, (unsigned char *)&k->ipv4_dst, 4);
        } else if (ntohs(k->n_proto) == 0x86dd) {
            hexcat(v6s, (unsigned char *)k->ipv6_src, 16);
            hexcat(v6d, (unsigned char *)k->ipv6_dst, 16);
        }
        printf("%s    {\"packet_hex\": \"%s\", \"disposition\": \"ok\", \"keys\": {"
               "\"nhoff\": %u, \"thoff\": %u, \"n_proto\": %u, \"addr_proto\": %u, "
               "\"ip_proto\": %u, \"sport\": %u, \"dport\": %u, "
               "\"ipv4_src\": \"%s\", \"ipv4_dst\": \"%s\", "
               "\"ipv6_src\": \"%s\", \"ipv6_dst\": \"%s\"}}",
               first ? "" : ",\n", phex,
               k->nhoff, k->thoff, ntohs(k->n_proto), ntohs(k->addr_proto),
               k->ip_proto, ntohs(k->sport), ntohs(k->dport),
               v4s, v4d, v6s, v6d);
        first = 0;
    }
    fclose(cf);
    printf("\n  ]\n}\n");
    return 0;
}
