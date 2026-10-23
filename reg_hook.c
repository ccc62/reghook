#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#if !defined(__aarch64__)
#error "RegHook supports ARM64/AArch64 only."
#endif

#ifndef __WALL
#define __WALL 0x40000000
#endif
#ifndef F_OWNER_TID
#define F_OWNER_TID 0
#endif
#ifndef TRAP_PERF
#define TRAP_PERF 6
#endif
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif

/* Linux AArch64 NT_PRSTATUS register layout. */
struct arm64_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

struct owner_ex_local { int type; pid_t pid; };
struct thread_entry { pid_t tid; int fd; int attached; int stopped; int stepping; };

static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_hits = 0;
static void stop_handler(int sig) { (void)sig; g_running = 0; }

static long perf_event_open_sys(struct perf_event_attr *attr, pid_t pid,
                                int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

/* Remove common invisible direction/format characters pasted by Android IMEs. */
static void clean_input(char *s) {
    unsigned char *r = (unsigned char *)s, *w = (unsigned char *)s;
    while (*r) {
        if (r[0] == 0xE2 && r[1] == 0x80 && r[2] >= 0x8E && r[2] <= 0x8F) { r += 3; continue; } /* LRM/RLM */
        if (r[0] == 0xE2 && r[1] == 0x80 && r[2] >= 0xAA && r[2] <= 0xAE) { r += 3; continue; } /* bidi controls */
        if (r[0] == 0xE2 && r[1] == 0x80 && r[2] == 0x8B) { r += 3; continue; } /* zero width space */
        if (r[0] == 0xEF && r[1] == 0xBB && r[2] == 0xBF) { r += 3; continue; } /* BOM */
        *w++ = *r++;
    }
    *w = '\0';
}

static int read_line(const char *prompt, char *buf, size_t size) {
    fputs(prompt, stdout); fflush(stdout);
    if (!fgets(buf, (int)size, stdin)) return -1;
    clean_input(buf);
    buf[strcspn(buf, "\r\n")] = '\0';
    /* trim leading/trailing ASCII whitespace */
    char *p = buf;
    while (*p == ' ' || *p == '\t') ++p;
    if (p != buf) memmove(buf, p, strlen(p) + 1);
    size_t n = strlen(buf);
    while (n && (buf[n-1] == ' ' || buf[n-1] == '\t')) buf[--n] = '\0';
    return 0;
}

static int parse_hex_u64(const char *s, uint64_t *out) {
    if (!s || !*s || !out) return -1;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s += 2;
    if (!*s) return -1;
    for (const char *p = s; *p; ++p) {
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F'))) return -1;
    }
    errno = 0;
    char *end = NULL;
    unsigned long long v = strtoull(s, &end, 16);
    if (errno || !end || *end) return -1;
    *out = (uint64_t)v;
    return 0;
}

static int parse_reg_index(const char *s, int *out) {
    if (!s || !*s || !out) return -1;
    if ((s[0] == 'x' || s[0] == 'X')) ++s;
    if (!*s) return -1;
    char *end = NULL;
    errno = 0;
    long v = strtol(s, &end, 10);
    if (errno || !end || *end || v < 0 || v > 30) return -1;
    *out = (int)v;
    return 0;
}

static int is_numeric(const char *s) {
    if (!s || !*s) return 0;
    for (; *s; ++s) if (*s < '0' || *s > '9') return 0;
    return 1;
}

static int attach_threads(pid_t pid, struct thread_entry **out, size_t *count) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/task", pid);
    DIR *d = opendir(path);
    if (!d) { fprintf(stderr, "[错误] 无法读取目标线程列表：%s\n", strerror(errno)); return -1; }
    struct thread_entry *items = NULL;
    size_t n = 0, cap = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (!is_numeric(ent->d_name)) continue;
        pid_t tid = (pid_t)strtol(ent->d_name, NULL, 10);
        if (cap == n) {
            size_t nc = cap ? cap * 2 : 16;
            struct thread_entry *tmp = realloc(items, nc * sizeof(*items));
            if (!tmp) { closedir(d); free(items); return -1; }
            items = tmp; cap = nc;
        }
        if (ptrace(PTRACE_SEIZE, tid, NULL, NULL) == -1) {
            fprintf(stderr, "[提示] TID %d seize 失败：%s\n", tid, strerror(errno));
            continue;
        }
        if (ptrace(PTRACE_INTERRUPT, tid, NULL, NULL) == -1) {
            fprintf(stderr, "[提示] TID %d interrupt 失败：%s\n", tid, strerror(errno));
            ptrace(PTRACE_DETACH, tid, NULL, NULL);
            continue;
        }
        int status = 0;
        if (waitpid(tid, &status, __WALL) == -1 || !WIFSTOPPED(status)) {
            fprintf(stderr, "[提示] TID %d 未能进入 ptrace 停止状态。\n", tid);
            ptrace(PTRACE_DETACH, tid, NULL, NULL);
            continue;
        }
        items[n++] = (struct thread_entry){ .tid = tid, .fd = -1, .attached = 1, .stopped = 1 };
    }
    closedir(d);
    *out = items; *count = n;
    return n ? 0 : -1;
}

static int add_breakpoint(struct thread_entry *t, uintptr_t addr) {
    struct perf_event_attr pe;
    memset(&pe, 0, sizeof(pe));
    pe.type = PERF_TYPE_BREAKPOINT;
    pe.size = sizeof(pe);
    pe.bp_type = HW_BREAKPOINT_X;
    pe.bp_addr = addr;
    pe.bp_len = HW_BREAKPOINT_LEN_4;
    pe.sample_period = 1;
    pe.disabled = 1;
    int fd = (int)perf_event_open_sys(&pe, t->tid, -1, -1, 0);
    if (fd < 0) {
        fprintf(stderr, "[提示] TID %d 设置硬件断点失败：%s\n", t->tid, strerror(errno));
        return -1;
    }
    struct owner_ex_local owner = { .type = F_OWNER_TID, .pid = t->tid };
    int flags = fcntl(fd, F_GETFL);
    if (fcntl(fd, F_SETOWN_EX, &owner) == -1 || fcntl(fd, F_SETSIG, SIGTRAP) == -1 ||
        flags == -1 || fcntl(fd, F_SETFL, flags | O_ASYNC) == -1 ||
        ioctl(fd, PERF_EVENT_IOC_RESET, 0) == -1 || ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) == -1) {
        fprintf(stderr, "[提示] TID %d 启用断点失败：%s\n", t->tid, strerror(errno));
        close(fd); return -1;
    }
    t->fd = fd;
    return 0;
}

static int get_regs(pid_t tid, struct arm64_regs *regs) {
    struct iovec iov = { .iov_base = regs, .iov_len = sizeof(*regs) };
    return ptrace(PTRACE_GETREGSET, tid, (void *)(uintptr_t)NT_PRSTATUS, &iov) == -1 ? -1 : 0;
}
static int set_regs(pid_t tid, struct arm64_regs *regs) {
    struct iovec iov = { .iov_base = regs, .iov_len = sizeof(*regs) };
    return ptrace(PTRACE_SETREGSET, tid, (void *)(uintptr_t)NT_PRSTATUS, &iov) == -1 ? -1 : 0;
}

static void cleanup(struct thread_entry *items, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (items[i].fd >= 0) { ioctl(items[i].fd, PERF_EVENT_IOC_DISABLE, 0); close(items[i].fd); }
    }
    /* PTRACE_DETACH requires a stopped tracee. Stop each still-running thread first. */
    for (size_t i = 0; i < n; ++i) {
        if (!items[i].attached) continue;
        if (!items[i].stopped) {
            if (ptrace(PTRACE_INTERRUPT, items[i].tid, NULL, NULL) == 0) {
                int status = 0;
                if (waitpid(items[i].tid, &status, __WALL) > 0 && WIFSTOPPED(status)) items[i].stopped = 1;
            } else if (errno == ESRCH) {
                items[i].attached = 0;
                continue;
            }
        }
        if (items[i].stopped) ptrace(PTRACE_DETACH, items[i].tid, NULL, NULL);
    }
    free(items);
}

static struct thread_entry *find_thread(struct thread_entry *items, size_t n, pid_t tid) {
    for (size_t i = 0; i < n; ++i) if (items[i].tid == tid) return &items[i];
    return NULL;
}

int main(void) {
    char buf[256];
    long pid_l;
    uint64_t addr_u, value_u;
    int reg_index;

    puts("========== RegHook v2 (ARM64 / ptrace) ==========");
    puts("说明：目标线程会在监控期间被 ptrace 跟踪；请先在自有测试程序验证。");
    if (read_line("目标 PID: ", buf, sizeof(buf)) || !*buf) { fprintf(stderr, "PID 输入无效。\n"); return 2; }
    errno = 0; char *end = NULL; pid_l = strtol(buf, &end, 10);
    if (errno || !end || *end || pid_l <= 0 || kill((pid_t)pid_l, 0) == -1) { fprintf(stderr, "PID 无效或进程不可访问。\n"); return 2; }
    if (read_line("硬件执行断点地址（十六进制）: ", buf, sizeof(buf)) || parse_hex_u64(buf, &addr_u) || !addr_u || (addr_u & 3)) {
        fprintf(stderr, "断点地址无效；请输入类似 70AA42C95C 或 0x70AA42C95C，且地址 4 字节对齐。\n"); return 2;
    }
    if (read_line("要修改的寄存器（X0-X30，也可输入数字）: ", buf, sizeof(buf)) || parse_reg_index(buf, &reg_index)) {
        fprintf(stderr, "寄存器无效；请输入 X8 或 8（范围 X0-X30）。\n"); return 2;
    }
    if (read_line("修改值（十六进制，例如 1F4 或 0x1F4）: ", buf, sizeof(buf)) || parse_hex_u64(buf, &value_u)) {
        fprintf(stderr, "修改值无效。请只输入十六进制数字，可带 0x 前缀；不可见字符会尝试自动清理。\n"); return 2;
    }

    printf("\n[配置确认] PID=%ld 地址=0x%llx 寄存器=X%d 写入值=0x%llx (%llu)\n",
           pid_l, (unsigned long long)addr_u, reg_index,
           (unsigned long long)value_u, (unsigned long long)value_u);
    puts("请核对以上配置；若不正确，按 Ctrl+C 退出。3 秒后尝试附加线程。\n");
    sleep(3);

    signal(SIGINT, stop_handler); signal(SIGTERM, stop_handler);
    struct thread_entry *threads = NULL; size_t n = 0;
    if (attach_threads((pid_t)pid_l, &threads, &n) != 0) {
        fprintf(stderr, "[失败] 没有成功附加任何线程。可能是权限/SELinux/目标进程状态限制。\n");
        free(threads); return 1;
    }
    size_t enabled = 0;
    for (size_t i = 0; i < n; ++i) if (add_breakpoint(&threads[i], (uintptr_t)addr_u) == 0) ++enabled;
    if (!enabled) {
        fprintf(stderr, "[失败] 所有线程的硬件断点设置都失败。\n");
        cleanup(threads, n); return 1;
    }
    for (size_t i = 0; i < n; ++i) {
        if (ptrace(PTRACE_CONT, threads[i].tid, NULL, NULL) == -1 && errno != ESRCH)
            fprintf(stderr, "[提示] TID %d 恢复执行失败：%s\n", threads[i].tid, strerror(errno));
        else threads[i].stopped = 0;
    }
    printf("[已启用] 成功设置 %zu/%zu 个线程的执行断点。\n", enabled, n);
    puts("命中时会尝试修改目标线程寄存器；新线程暂不自动加入。Ctrl+C 停止。\n");

    while (g_running) {
        int status = 0;
        pid_t tid = waitpid(-1, &status, __WALL | WNOHANG);
        if (tid == 0) { usleep(10000); continue; }
        if (tid < 0) {
            if (errno == EINTR) continue;
            if (errno == ECHILD) { fprintf(stderr, "\n[错误] 已没有可等待的跟踪线程。\n"); break; }
            usleep(10000); continue;
        }
        struct thread_entry *te = find_thread(threads, n, tid);
        if (WIFEXITED(status) || WIFSIGNALED(status)) { if (te) { te->attached = 0; te->stopped = 0; } continue; }
        if (!WIFSTOPPED(status)) continue;
        if (te) te->stopped = 1;
        int sig = WSTOPSIG(status);
        int deliver = sig;
        int do_single_step = 0;
        if (sig == SIGTRAP && te && te->stepping) {
            /* This is the single-step trap after executing the instruction at the BP. */
            if (te->fd >= 0 && ioctl(te->fd, PERF_EVENT_IOC_ENABLE, 0) == -1)
                fprintf(stderr, "\n[提示] TID %d 重新启用断点失败：%s\n", tid, strerror(errno));
            te->stepping = 0;
            deliver = 0;
        } else if (sig == SIGTRAP) {
            siginfo_t si; memset(&si, 0, sizeof(si));
            int have_si = ptrace(PTRACE_GETSIGINFO, tid, NULL, &si) == 0;
            struct arm64_regs regs;
            if (have_si && si.si_code == TRAP_PERF && te && te->fd >= 0 && get_regs(tid, &regs) == 0) {
                /* Disable this thread's BP while single-stepping the trapped instruction,
                   otherwise resuming at the same PC can immediately retrigger forever. */
                ioctl(te->fd, PERF_EVENT_IOC_DISABLE, 0);
                if (regs.pc == addr_u || regs.pc == addr_u + 4) {
                    regs.regs[reg_index] = value_u;
                    if (set_regs(tid, &regs) == 0) {
                        ++g_hits;
                        if ((g_hits % 10) == 1)
                            printf("\r命中并写回：%d 次（最近 TID=%d，PC=0x%llx）   ", (int)g_hits, tid, (unsigned long long)regs.pc);
                        fflush(stdout);
                    } else {
                        fprintf(stderr, "\n[错误] TID %d 写回寄存器失败：%s\n", tid, strerror(errno));
                    }
                }
                te->stepping = 1;
                do_single_step = 1;
                deliver = 0; /* consume perf-generated SIGTRAP */
            }
        }
        if (do_single_step) {
            if (ptrace(PTRACE_SINGLESTEP, tid, NULL, NULL) == -1 && errno != ESRCH) {
                fprintf(stderr, "\n[提示] TID %d 单步执行失败：%s\n", tid, strerror(errno));
                if (te) te->stepping = 0;
                if (te && te->fd >= 0) ioctl(te->fd, PERF_EVENT_IOC_ENABLE, 0);
                if (ptrace(PTRACE_CONT, tid, NULL, NULL) == 0 && te) te->stopped = 0;
            } else if (te) te->stopped = 0;
            continue;
        }
        if (ptrace(PTRACE_CONT, tid, NULL, (void *)(intptr_t)deliver) == -1 && errno != ESRCH) {
            if (errno != EIO) fprintf(stderr, "\n[提示] TID %d 继续执行失败：%s\n", tid, strerror(errno));
        } else if (te) te->stopped = 0;
    }
    puts("\n正在清理断点并分离线程……");
    cleanup(threads, n);
    printf("已停止。寄存器写回成功次数：%d\n", (int)g_hits);
    return 0;
}
