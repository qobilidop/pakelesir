// Golden factory: load the flow-dissector program (raw .text) and, for
// each corpus packet, BPF_PROG_TEST_RUN it in the kernel, decoding the
// returned bpf_flow_keys into a GoldenFile JSON on stdout (schema matches
// src/oracle/flow_dissector.rs serde types).
//
// Usage: capture <prog.text> <corpus.txt>
#include <linux/bpf.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <arpa/inet.h>

static int sys_bpf(int cmd, union bpf_attr *a, unsigned s) {
    return syscall(SYS_bpf, cmd, a, s);
}

static int load_prog(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("fopen prog"); exit(1); }
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    void *insns = malloc(sz);
    if (fread(insns, 1, sz, f) != (size_t)sz) { perror("fread prog"); exit(1); }
    fclose(f);
    static char log[16384];
    union bpf_attr attr; memset(&attr, 0, sizeof attr);
    attr.prog_type = BPF_PROG_TYPE_FLOW_DISSECTOR;
    attr.insn_cnt = sz / 8;
    attr.insns = (uint64_t)insns;
    attr.license = (uint64_t)"GPL";
    attr.log_level = 1; attr.log_buf = (uint64_t)log; attr.log_size = sizeof log;
    int fd = sys_bpf(BPF_PROG_LOAD, &attr, sizeof attr);
    if (fd < 0) {
        fprintf(stderr, "PROG_LOAD failed errno=%d (%s)\n%s\n", errno, strerror(errno), log);
        exit(1);
    }
    return fd;
}

// hex string -> bytes; returns length, -1 on error.
static int unhex(const char *s, unsigned char *out, int cap) {
    int n = 0;
    for (; s[0] && s[1] && s[0] != '\n'; s += 2) {
        if (n >= cap) return -1;
        unsigned v;
        if (sscanf(s, "%2x", &v) != 1) return -1;
        out[n++] = (unsigned char)v;
    }
    return n;
}

static void hexcat(char *dst, const unsigned char *b, int n) {
    for (int i = 0; i < n; i++) sprintf(dst + i * 2, "%02x", b[i]);
    dst[n * 2] = 0;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: %s <prog.text> <corpus.txt>\n", argv[0]); return 2; }
    int prog_fd = load_prog(argv[1]);

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
        union bpf_attr t; memset(&t, 0, sizeof t);
        t.test.prog_fd = prog_fd;
        t.test.data_in = (uint64_t)pkt; t.test.data_size_in = plen;
        t.test.data_out = (uint64_t)out; t.test.data_size_out = sizeof out;
        t.test.repeat = 1;
        if (sys_bpf(BPF_PROG_TEST_RUN, &t, sizeof t) < 0) {
            fprintf(stderr, "TEST_RUN failed errno=%d (%s)\n", errno, strerror(errno));
            return 1;
        }
        struct bpf_flow_keys *k = (struct bpf_flow_keys *)out;

        char phex[4200]; hexcat(phex, pkt, plen);
        char v4s[9] = "", v4d[9] = "", v6s[33] = "", v6d[33] = "";
        if (ntohs(k->n_proto) == 0x0800) {
            hexcat(v4s, (unsigned char *)&k->ipv4_src, 4);
            hexcat(v4d, (unsigned char *)&k->ipv4_dst, 4);
        } else if (ntohs(k->n_proto) == 0x86dd) {
            hexcat(v6s, (unsigned char *)k->ipv6_src, 16);
            hexcat(v6d, (unsigned char *)k->ipv6_dst, 16);
        }
        printf("%s    {\"packet_hex\": \"%s\", \"keys\": {"
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
