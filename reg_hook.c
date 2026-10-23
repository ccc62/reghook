#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

/*
 * RegHook v1 — ARM64 Linux/Android proof of concept.
 * A perf hardware execution breakpoint requests SIGTRAP for the owning TID.
 * The signal handler edits the interrupted thread's ucontext before signal return.
 *
 * This is a prototype, not yet validated on the user's specific Android 5.4 kernel.
 */
#ifndef __aarch64__
#error "RegHook v1 supports AArch64/ARM64 only."
#endif

#ifndef F_OWNER_TID
#define F_OWNER_TID 0
struct f_owner_ex { int type; pid_t pid; };
#endif

static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_hits = 0;
static volatile sig_atomic_t g_reg_index = 0;
static volatile uint64_t g_value = 0;
static volatile uintptr_t g_bp_addr = 0;

static void on_sigtrap(int sig, siginfo_t *info, void *context) {
    (void)info;
    if (sig != SIGTRAP || !context) return;
    ucontext_t *uc = (ucontext_t *)context;
    /* Linux AArch64 ucontext: mcontext.regs[0..30], pc, sp, pstate. */
    int n = (int)g_reg_index;
    if (n >= 0 && n <= 30) {
        uc->uc_mcontext.regs[n] = (unsigned long)g_value;
        g_hits++;
    }
}

static long perf_event_open_sys(struct perf_event_attr *attr, pid_t pid,
                                int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int add_thread(pid_t tid, uintptr_t addr) {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_BREAKPOINT;
    pe.size = sizeof(pe);
    pe.bp_type = HW_BREAKPOINT_X;
    pe.bp_addr = addr;
    pe.bp_len = HW_BREAKPOINT_LEN_4;
    pe.sample_period = 1;
    pe.sample_type = PERF_SAMPLE_IP;
    pe.wakeup_events = 1;
    pe.disabled = 1;

    int fd = (int)perf_event_open_sys(&pe, tid, -1, -1, 0);
    if (fd < 0) {
        fprintf(stderr, "[!] TID %d: perf_event_open failed: %s\n", tid, strerror(errno));
        return -1;
    }

    struct f_owner_ex owner;
    owner.type = F_OWNER_TID;
    owner.pid = tid;
    if (fcntl(fd, F_SETOWN_EX, &owner) == -1 ||
        fcntl(fd, F_SETSIG, SIGTRAP) == -1 ||
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_ASYNC) == -1) {
        fprintf(stderr, "[!] TID %d: async signal setup failed: %s\n", tid, strerror(errno));
        close(fd);
        return -1;
    }
    if (ioctl(fd, PERF_EVENT_IOC_RESET, 0) == -1 ||
        ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) == -1) {
        fprintf(stderr, "[!] TID %d: enabling breakpoint failed: %s\n", tid, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static int is_numeric(const char *s) {
    if (!s || !*s) return 0;
    for (; *s; ++s) if (*s < '0' || *s > '9') return 0;
    return 1;
}

static int install_for_existing_threads(pid_t pid, uintptr_t addr, int **fds_out, size_t *n_out) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);
    DIR *d = opendir(path);
    if (!d) {
        fprintf(stderr, "[!] Cannot list target threads: %s\n", strerror(errno));
        return -1;
    }
    int *fds = NULL;
    size_t n = 0, cap = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (!is_numeric(ent->d_name)) continue;
        pid_t tid = (pid_t)atoi(ent->d_name);
        if (n == cap) {
            size_t nc = cap ? cap * 2 : 8;
            int *tmp = realloc(fds, nc * sizeof(int));
            if (!tmp) { closedir(d); free(fds); return -1; }
            fds = tmp; cap = nc;
        }
        int fd = add_thread(tid, addr);
        if (fd >= 0) fds[n++] = fd;
    }
    closedir(d);
    *fds_out = fds;
    *n_out = n;
    return n ? 0 : -1;
}

static void stop_handler(int sig) { (void)sig; g_running = 0; }

int main(void) {
    char buf[128];
    long pid_l, reg_l;
    unsigned long long addr_u, value_u;

    printf("========== RegHook v1 (ARM64) ==========\n");
    printf("注意：这是实验性原型；请先在自己的测试程序上验证。\n");
    printf("目标 PID: ");
    if (!fgets(buf, sizeof(buf), stdin) || (pid_l = strtol(buf, NULL, 10)) <= 0) {
        fprintf(stderr, "无效 PID\n"); return 2;
    }
    printf("硬件执行断点地址（十六进制，例如 0x70001234）: ");
    if (!fgets(buf, sizeof(buf), stdin) || sscanf(buf, "%llx", &addr_u) != 1 || !addr_u || (addr_u & 3)) {
        fprintf(stderr, "地址无效；ARM64 指令地址应至少 4 字节对齐。\n"); return 2;
    }
    printf("要修改的寄存器编号（0-30，对应 X0-X30）: ");
    if (!fgets(buf, sizeof(buf), stdin) || (reg_l = strtol(buf, NULL, 10)) < 0 || reg_l > 30) {
        fprintf(stderr, "寄存器编号必须为 0-30。\n"); return 2;
    }
    printf("修改值（十六进制，例如 0x3e7）: ");
    if (!fgets(buf, sizeof(buf), stdin) || sscanf(buf, "%llx", &value_u) != 1) {
        fprintf(stderr, "修改值无效。\n"); return 2;
    }

    g_bp_addr = (uintptr_t)addr_u;
    g_reg_index = (sig_atomic_t)reg_l;
    g_value = (uint64_t)value_u;

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_sigtrap;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    sigaddset(&sa.sa_mask, SIGTRAP);
    if (sigaction(SIGTRAP, &sa, NULL) == -1) {
        perror("sigaction"); return 1;
    }
    signal(SIGINT, stop_handler);
    signal(SIGTERM, stop_handler);

    int *fds = NULL;
    size_t n = 0;
    if (install_for_existing_threads((pid_t)pid_l, (uintptr_t)addr_u, &fds, &n) != 0) {
        fprintf(stderr, "\n[失败] 没有在线程上成功设置硬件断点。\n");
        fprintf(stderr, "可能原因：内核未开放 perf 硬件断点、权限限制、地址无效或硬件槽位不足。\n");
        free(fds); return 1;
    }

    printf("\n[已请求] 对 %zu 个现存线程设置执行断点。\n", n);
    printf("地址=0x%llx，目标=X%ld，写入值=0x%llx\n", addr_u, reg_l, value_u);
    printf("Ctrl+C 停止。注意：新创建的线程不会自动加入本版监控。\n");

    while (g_running) {
        sleep(1);
        printf("\r命中次数（信号回调计数）: %d   ", (int)g_hits);
        fflush(stdout);
    }
    for (size_t i = 0; i < n; ++i) {
        ioctl(fds[i], PERF_EVENT_IOC_DISABLE, 0);
        close(fds[i]);
    }
    free(fds);
    printf("\n已停止。\n");
    return 0;
}
