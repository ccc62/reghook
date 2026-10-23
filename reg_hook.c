#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
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
#ifndef NT_PRSTATUS
#define NT_PRSTATUS 1
#endif
#ifndef NT_ARM_HW_BREAK
#define NT_ARM_HW_BREAK 0x402
#endif
#ifndef TRAP_HWBKPT
#define TRAP_HWBKPT 4
#endif
#ifndef TRAP_TRACE
#define TRAP_TRACE 2
#endif

#define MAX_HW_BREAKS 16

struct arm64_regs {
    uint64_t regs[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
};

struct hw_break_reg { uint64_t addr; uint32_t ctrl; uint32_t pad; };
struct hw_break_state { uint32_t dbg_info; uint32_t pad; struct hw_break_reg dbg_regs[MAX_HW_BREAKS]; };

struct thread_entry {
    pid_t tid;
    int attached;
    int stopped;
    int stepping;
    int slot;
    int have_hw_state;
    int monitoring;
    struct hw_break_state original;
    struct hw_break_state enabled_state;
};

static volatile sig_atomic_t g_running = 1;
static unsigned long long g_hits = 0;              /* 成功写回寄存器 */
static unsigned long long g_hw_hits = 0;           /* 识别到的硬件断点事件 */
static unsigned long long g_write_failures = 0;
static unsigned long long g_step_failures = 0;
static unsigned long long g_reenable_failures = 0;
static unsigned long long g_continue_failures = 0;
static unsigned long long g_restore_failures = 0;
static unsigned long long g_detach_failures = 0;
static unsigned long long g_unexpected_stops = 0;
static unsigned long long g_attach_failures = 0;
static unsigned long long g_setup_failures = 0;
static unsigned long long g_reg_read_failures = 0;
static unsigned long long g_cleanup_stop_failures = 0;
static unsigned long long g_threads_found = 0;
static unsigned long long g_threads_attached = 0;
static unsigned long long g_threads_resumed = 0;
static int g_verbose = 0;
static void stop_handler(int sig) { (void)sig; g_running = 0; }

static void clean_input(char *s) {
    /* Strip common invisible Unicode formatting characters without reading
       beyond the NUL terminator (the previous byte-lookahead could do that). */
    size_t n = strlen(s), r = 0, w = 0;
    while (r < n) {
        if (r + 2 < n && (unsigned char)s[r] == 0xE2 &&
            (unsigned char)s[r + 1] == 0x80) {
            unsigned char c = (unsigned char)s[r + 2];
            if ((c >= 0x8A && c <= 0x8F) || (c >= 0xAA && c <= 0xAE) || c == 0x8B) {
                r += 3;
                continue;
            }
        }
        if (r + 2 < n && (unsigned char)s[r] == 0xEF &&
            (unsigned char)s[r + 1] == 0xBB && (unsigned char)s[r + 2] == 0xBF) {
            r += 3;
            continue;
        }
        s[w++] = s[r++];
    }
    s[w] = '\0';
}

static int read_line(const char *prompt, char *buf, size_t size) {
    for (;;) {
        fputs(prompt, stdout);
        fflush(stdout);
        if (!fgets(buf, (int)size, stdin)) return -1;
        size_t n = strlen(buf);
        int has_newline = n > 0 && buf[n - 1] == '\n';
        if (!has_newline && !feof(stdin)) {
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF) { }
            puts("输入过长，已丢弃多余字符，请重新输入。\n");
            continue;
        }
        clean_input(buf);
        buf[strcspn(buf, "\r\n")] = '\0';
        char *p = buf;
        while (*p == ' ' || *p == '\t') ++p;
        if (p != buf) memmove(buf, p, strlen(p) + 1);
        n = strlen(buf);
        while (n && (buf[n - 1] == ' ' || buf[n - 1] == '\t')) buf[--n] = '\0';
        return 0;
    }
}
static int parse_hex_u64(const char *s,uint64_t *out) {
    if(!s||!*s||!out)return -1; if(s[0]=='0'&&(s[1]=='x'||s[1]=='X'))s+=2; if(!*s)return -1;
    for(const char*p=s;*p;++p)if(!((*p>='0'&&*p<='9')||(*p>='a'&&*p<='f')||(*p>='A'&&*p<='F')))return -1;
    errno=0; char *end=NULL; unsigned long long v=strtoull(s,&end,16); if(errno||!end||*end)return -1; *out=(uint64_t)v; return 0;
}
static int parse_reg_index(const char*s,int*out){if(!s||!*s||!out)return -1;if(*s=='x'||*s=='X')++s;if(!*s)return -1;errno=0;char*e=NULL;long v=strtol(s,&e,10);if(errno||!e||*e||v<0||v>30)return -1;*out=(int)v;return 0;}
static int is_numeric(const char*s){if(!s||!*s)return 0;for(;*s;++s)if(*s<'0'||*s>'9')return 0;return 1;}

/* Returns 1 if addr lies in an executable mapping, 0 if maps was readable
   but no executable mapping matched, and -1 if maps could not be inspected. */
static int address_is_executable(pid_t pid, uint64_t addr) {
    char path[128], line[1024];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    int found = 0;
    while (fgets(line, sizeof(line), fp)) {
        unsigned long long lo = 0, hi = 0;
        char perms[5] = {0};
        if (sscanf(line, "%llx-%llx %4s", &lo, &hi, perms) == 3 &&
            addr >= (uint64_t)lo && addr < (uint64_t)hi && perms[2] == 'x') {
            found = 1;
            break;
        }
    }
    fclose(fp);
    return found;
}
static int get_regs(pid_t tid,struct arm64_regs*r){struct iovec i={r,sizeof(*r)};return ptrace(PTRACE_GETREGSET,tid,(void*)(uintptr_t)NT_PRSTATUS,&i)==-1?-1:0;}
static int set_regs(pid_t tid,struct arm64_regs*r){struct iovec i={r,sizeof(*r)};return ptrace(PTRACE_SETREGSET,tid,(void*)(uintptr_t)NT_PRSTATUS,&i)==-1?-1:0;}
static int get_hw_state(pid_t tid,struct hw_break_state*s){memset(s,0,sizeof(*s));struct iovec i={s,sizeof(*s)};if(ptrace(PTRACE_GETREGSET,tid,(void*)(uintptr_t)NT_ARM_HW_BREAK,&i)==-1)return -1;return 0;}
static int set_hw_state(pid_t tid,struct hw_break_state*s,unsigned int slots){
    /* Limit SETREGSET to the slot prefix being changed; don't write all 16. */
    if(slots==0) return 0;
    if(slots>MAX_HW_BREAKS) slots=MAX_HW_BREAKS;
    size_t len=offsetof(struct hw_break_state,dbg_regs)+(size_t)slots*sizeof(struct hw_break_reg);
    struct iovec i={s,len};
    return ptrace(PTRACE_SETREGSET,tid,(void*)(uintptr_t)NT_ARM_HW_BREAK,&i)==-1?-1:0;
 }

static void cleanup(struct thread_entry *a, size_t n);

static int attach_threads(pid_t pid,struct thread_entry **out,size_t *count){
    char path[128];snprintf(path,sizeof(path),"/proc/%d/task",pid);DIR*d=opendir(path);if(!d){fprintf(stderr,"[错误] 无法读取线程列表：%s\n",strerror(errno));return -1;}
    struct thread_entry*items=NULL;size_t n=0,cap=0;struct dirent*e;
    while((e=readdir(d))){if(!is_numeric(e->d_name))continue;pid_t tid=(pid_t)strtol(e->d_name,NULL,10); g_threads_found++;
        if(cap==n){size_t nc=cap?cap*2:16;void*p=realloc(items,nc*sizeof(*items));if(!p){closedir(d);cleanup(items,n);return -1;}items=p;cap=nc;}
        if(ptrace(PTRACE_SEIZE,tid,NULL,NULL)==-1){g_attach_failures++;if(g_verbose)fprintf(stderr,"[提示] TID %d 附加失败：%s\n",tid,strerror(errno));continue;}
        if(ptrace(PTRACE_INTERRUPT,tid,NULL,NULL)==-1){
            int saved=errno; g_attach_failures++;
            if(g_verbose)fprintf(stderr,"[提示] TID %d 中断失败：%s\n",tid,strerror(saved));
            if(ptrace(PTRACE_DETACH,tid,NULL,NULL)==-1 && errno!=ESRCH){
                /* Keep an entry so final cleanup can retry interrupt/detach. */
                memset(&items[n],0,sizeof(items[n])); items[n].tid=tid;
                items[n].attached=1; items[n].stopped=0; items[n].slot=-1; n++;
            }
            continue;
        }
        int st=0;pid_t wr;do{wr=waitpid(tid,&st,__WALL);}while(wr==-1&&errno==EINTR);
        if(wr!=tid||!WIFSTOPPED(st)){
            g_attach_failures++;
            if(g_verbose)fprintf(stderr,"[提示] TID %d 未进入停止状态。\n",tid);
            if(ptrace(PTRACE_DETACH,tid,NULL,NULL)==-1 && errno!=ESRCH){
                memset(&items[n],0,sizeof(items[n])); items[n].tid=tid;
                items[n].attached=1; items[n].stopped=0; items[n].slot=-1; n++;
            }
            continue;
        }
        memset(&items[n],0,sizeof(items[n]));items[n].tid=tid;items[n].attached=1;items[n].stopped=1;items[n].slot=-1;n++;
    }
    closedir(d);*out=items;*count=n;g_threads_attached=n;return n?0:-1;
}
static int setup_hw_break(struct thread_entry*t,uint64_t addr){
    struct hw_break_state s;if(get_hw_state(t->tid,&s)==-1){if(g_verbose)fprintf(stderr,"[提示] TID %d 读取硬件断点状态失败：%s\n",t->tid,strerror(errno));return -1;}
    unsigned int slots=s.dbg_info&0xffu;if(slots>MAX_HW_BREAKS)slots=MAX_HW_BREAKS;
    if(!slots){if(g_verbose)fprintf(stderr,"[提示] TID %d 内核报告没有硬件执行断点槽位。\n",t->tid);return -1;}
    int slot=-1;for(unsigned int i=0;i<slots;i++)if(!(s.dbg_regs[i].ctrl&1u)){slot=(int)i;break;}
    if(slot<0){if(g_verbose)fprintf(stderr,"[提示] TID %d 没有空闲硬件断点槽位。\n",t->tid);return -1;}
    t->original=s;t->enabled_state=s;t->slot=slot;t->have_hw_state=1;
    t->enabled_state.dbg_regs[slot].addr=addr;
    /* E=1, PMC=EL0 (10b), BAS=all four instruction bytes. */
    t->enabled_state.dbg_regs[slot].ctrl=1u|(2u<<1)|(0xFu<<5);
    t->enabled_state.dbg_regs[slot].pad=0;
    if(set_hw_state(t->tid,&t->enabled_state,(unsigned int)slot+1)==-1){
        int saved_errno=errno;
        if(g_verbose)fprintf(stderr,"[提示] TID %d 写入硬件断点失败：errno=%d (%s)，dbg_info=0x%08x，报告槽位数=%u，写入长度=%zu 字节\n",
            t->tid,saved_errno,strerror(saved_errno),s.dbg_info,slots,
            offsetof(struct hw_break_state,dbg_regs)+((size_t)slot+1)*sizeof(struct hw_break_reg));
        /* Keep saved state so cleanup can still attempt restoration. */ return -1;
    }
    t->monitoring=1;
    if(g_verbose)printf("[诊断] TID %d: dbg_info=0x%08x, 硬件断点槽位=%u, 使用槽位=%d\n",
        t->tid,s.dbg_info,slots,slot);
    return 0;
}
static int set_thread_break_enabled(struct thread_entry*t,int enabled){
    if(!t->have_hw_state||t->slot<0)return -1;
    struct hw_break_state s=t->enabled_state;
    s.dbg_regs[t->slot].ctrl=enabled?t->enabled_state.dbg_regs[t->slot].ctrl:0;
    return set_hw_state(t->tid,&s,(unsigned int)t->slot+1);
 }
static struct thread_entry*find_thread(struct thread_entry*a,size_t n,pid_t tid){for(size_t i=0;i<n;i++)if(a[i].tid==tid)return &a[i];return NULL;}
static void cleanup(struct thread_entry *a, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (!a[i].attached) continue;
        if (!a[i].stopped) {
            if (ptrace(PTRACE_INTERRUPT, a[i].tid, NULL, NULL) == 0) {
                int st = 0;
                pid_t w;
                do { w = waitpid(a[i].tid, &st, __WALL); }
                while (w == -1 && errno == EINTR);
                if (w == a[i].tid && WIFSTOPPED(st)) a[i].stopped = 1;
                else if (w == -1 && errno == ECHILD) {
                    a[i].attached = 0;
                    continue;
                }
            } else if (errno == ESRCH || errno == ECHILD) {
                a[i].attached = 0;
                continue;
            }
        }
        if (!a[i].stopped) {
            /* PTRACE_DETACH requires a ptrace-stop. Do not pretend that a
               detach succeeded or discard this failure from the summary. */
            g_cleanup_stop_failures++;
            fprintf(stderr, "[严重警告] TID %d 未能确认停止，跳过硬件状态恢复；尝试最后一次分离。\n", a[i].tid);
            if (ptrace(PTRACE_DETACH, a[i].tid, NULL, NULL) == -1 && errno != ESRCH) {
                g_detach_failures++;
                fprintf(stderr, "[严重警告] TID %d 最后尝试分离也失败：errno=%d (%s)\n", a[i].tid, errno, strerror(errno));
            }
            continue;
        }
        if (a[i].have_hw_state && a[i].slot >= 0 &&
            set_hw_state(a[i].tid, &a[i].original, (unsigned int)a[i].slot + 1) == -1) {
            g_restore_failures++;
            fprintf(stderr, "[警告] TID %d 恢复原硬件断点状态失败：errno=%d (%s)\n",
                    a[i].tid, errno, strerror(errno));
        }
        if (ptrace(PTRACE_DETACH, a[i].tid, NULL, NULL) == -1 && errno != ESRCH) {
            g_detach_failures++;
            fprintf(stderr, "[错误] TID %d 分离失败：errno=%d (%s)\n", a[i].tid, errno, strerror(errno));
        }
    }
    free(a);
}

int main(void){
    char b[256]; long pid_l=0; uint64_t addr=0,val=0; int ri=0;
    puts("========== RegHook v6.2 (ARM64 ptrace HW breakpoint) ==========");
    puts("提示：实验版本；会暂停并跟踪目标线程。仅在自有测试进程中验证。");
    puts("输入提示：除 PID 外，输入 q 可返回上一步。");

retry_pid:
    addr=0; val=0; ri=0;
    for (;;) {
        if (read_line("目标 PID: ", b, sizeof(b)) < 0) return 2;
        if (!strcmp(b,"q") || !strcmp(b,"Q")) return 0;
        errno=0; char *e=NULL; long candidate=strtol(b,&e,10);
        if (!*b || errno || !e || *e || candidate<=0 || candidate>INT_MAX ||
            kill((pid_t)candidate,0)==-1) {
            puts("PID 无效或进程不可访问，请重新输入 PID。\n");
            continue;
        }
        pid_l=candidate; break;
    }
retry_addr:
    val=0; ri=0;
    for (;;) {
        if (read_line("硬件执行断点地址（十六进制）: ", b, sizeof(b)) < 0) return 2;
        if (!strcmp(b,"q") || !strcmp(b,"Q")) goto retry_pid;
        if (parse_hex_u64(b,&addr) || !addr || (addr&3)) {
            puts("断点地址无效；须为非零且 4 字节对齐的代码地址，请重新输入地址。\n");
            continue;
        }
        int executable = address_is_executable((pid_t)pid_l, addr);
        if (executable == 0) {
            puts("警告：该地址不在目标进程的可执行内存映射中，请检查地址是否来自当前进程和当前运行状态。\n");
            continue;
        }
        if (executable < 0) {
            puts("[提示] 无法读取目标进程 maps，跳过可执行映射校验。\n");
        }
        break;
    }
retry_reg:
    val=0;
    for (;;) {
        if (read_line("要修改的寄存器（X0-X30，也可输入数字）: ", b, sizeof(b)) < 0) return 2;
        if (!strcmp(b,"q") || !strcmp(b,"Q")) goto retry_addr;
        if (parse_reg_index(b,&ri)) {
            puts("寄存器无效；请输入 X8 或 8，请重新输入寄存器。\n");
            continue;
        }
        break;
    }
    for (;;) {
        if (read_line("修改值（十六进制）: ", b, sizeof(b)) < 0) return 2;
        if (!strcmp(b,"q") || !strcmp(b,"Q")) goto retry_reg;
        if (parse_hex_u64(b,&val)) {
            puts("修改值无效；请输入十六进制数值，请重新输入修改值。\n");
            continue;
        }
        break;
    }
    if (read_line("显示逐线程详细诊断？默认 N（输入 y 开启）: ",b,sizeof(b)) < 0) return 2;
    g_verbose = (b[0]=='y'||b[0]=='Y'||b[0]=='1');
    printf("\n[配置确认] PID=%ld 地址=0x%llx 寄存器=X%d 写入值=0x%llx (%llu)\n",
           pid_l,(unsigned long long)addr,ri,(unsigned long long)val,(unsigned long long)val);
    printf("诊断模式：%s。3 秒后附加线程；按 Ctrl+C 停止。\n\n",g_verbose?"详细":"简洁");
    fflush(stdout); sleep(3);
    signal(SIGINT,stop_handler); signal(SIGTERM,stop_handler);
    struct thread_entry*ts=NULL; size_t n=0;
    if (attach_threads((pid_t)pid_l,&ts,&n)) {
        fprintf(stderr,"[失败] 没有成功附加线程（附加/停止失败次数：%llu）。\n",g_attach_failures);
        free(ts); return 1;
    }
    size_t enabled=0;
    for(size_t i=0;i<n;i++) {
        if (!ts[i].attached || !ts[i].stopped) {
            g_setup_failures++;
            if (g_verbose) fprintf(stderr, "[提示] TID %d 未确认处于停止状态，跳过断点安装。\n", ts[i].tid);
            continue;
        }
        if(setup_hw_break(&ts[i],addr)==0) enabled++;
        else g_setup_failures++;
    }
    if(!enabled) {
        fprintf(stderr,"[失败] 没有线程能设置硬件执行断点；配置失败线程数：%llu，正在恢复并分离。\n",g_setup_failures);
        cleanup(ts,n); return 1;
    }
    size_t resumed = 0;
    int startup_resume_failed = 0;
    for (size_t i = 0; i < n; i++) {
        if (!ts[i].attached || !ts[i].stopped) continue;
        if (ptrace(PTRACE_CONT, ts[i].tid, NULL, NULL) == 0) {
            ts[i].stopped = 0;
            resumed++;
        } else if (errno == ESRCH) {
            ts[i].attached = 0;
            ts[i].stopped = 0;
        } else {
            g_continue_failures++;
            startup_resume_failed = 1;
            fprintf(stderr, "[严重警告] TID %d 恢复运行失败：errno=%d (%s)；将停止监控并清理，避免线程长期暂停。\n",
                    ts[i].tid, errno, strerror(errno));
        }
    }
    g_threads_resumed = resumed;
    printf("[线程统计] 发现线程=%llu，已附加并记录=%llu，成功安装断点=%zu，成功恢复运行=%zu。\n",
           g_threads_found, g_threads_attached, enabled, resumed);
    if (startup_resume_failed) g_running = 0;
    puts("本版仍为实验版本；不会自动跟踪之后新建的线程。命中后会验证单步停止类型，再尝试重新启用断点。按 Ctrl+C 停止。\n");
    while(g_running){int st=0;pid_t tid=waitpid(-1,&st,__WALL|WNOHANG);if(tid==0){usleep(10000);continue;}if(tid<0){if(errno==EINTR)continue;if(errno==ECHILD){fputs("\n[提示] 当前没有可等待的跟踪线程；目标可能已退出，或跟踪关系已丢失。\n",stderr);break;}fprintf(stderr,"\n[错误] waitpid 失败：errno=%d (%s)；停止监控并清理。\n",errno,strerror(errno));g_running=0;break;}
        struct thread_entry*t=find_thread(ts,n,tid);if(WIFEXITED(st)||WIFSIGNALED(st)){if(t){t->attached=0;t->stopped=0;}continue;}if(!WIFSTOPPED(st))continue;if(t)t->stopped=1;
        int sig=WSTOPSIG(st),deliver=sig;siginfo_t si;memset(&si,0,sizeof(si));int have_si=(ptrace(PTRACE_GETSIGINFO,tid,NULL,&si)==0);
        /* PTRACE_SINGLESTEP should normally end with SIGTRAP/TRAP_TRACE.
           Do not mistake every SIGTRAP (for example, another HW breakpoint)
           for completion of the single-step. */
        if (t && t->stepping && sig == SIGTRAP && have_si && si.si_code == TRAP_TRACE) {
            if (t->have_hw_state && set_thread_break_enabled(t, 1) == -1) {
                g_reenable_failures++;
                t->monitoring = 0;
                fprintf(stderr, "\n[警告] TID %d 单步完成后重新启用断点失败；该线程将继续运行但停止监控：errno=%d (%s)\n", tid, errno, strerror(errno));
            }
            t->stepping = 0;
            deliver = 0;
        } else {
            /* A signal may interrupt SINGLESTEP before the instruction at the
               target PC has executed. Re-enabling there can immediately retrap.
               Inspect PC first; if uncertain, leave this thread unmonitored. */
            if (t && t->stepping) {
                struct arm64_regs step_regs;
                int have_step_regs = get_regs(tid, &step_regs) == 0;
                if (!have_step_regs) {
                    g_reg_read_failures++;
                    t->monitoring = 0;
                    fprintf(stderr, "\n[警告] TID %d 单步被其他停止打断且无法读取 PC；为避免断点循环，该线程将停止监控。\n", tid);
                } else if (step_regs.pc == addr) {
                    t->monitoring = 0;
                    fprintf(stderr, "\n[提示] TID %d 单步中断时 PC 仍在目标地址；本次不重新启用断点，避免重复触发。该线程将停止监控。\n", tid);
                } else if (t->have_hw_state && set_thread_break_enabled(t, 1) == -1) {
                    g_reenable_failures++;
                    t->monitoring = 0;
                    fprintf(stderr, "\n[警告] TID %d 单步被其他停止打断，重新启用断点失败；该线程将停止监控：errno=%d (%s)\n", tid, errno, strerror(errno));
                }
                t->stepping = 0;
            }
            if (t && t->monitoring && sig == SIGTRAP && have_si && si.si_code == TRAP_HWBKPT) {
                struct arm64_regs r;
                if (get_regs(tid, &r) == -1) {
                    g_reg_read_failures++;
                    g_unexpected_stops++;
                    fprintf(stderr, "\n[严重警告] TID %d 收到硬件断点，但无法读取寄存器；停止监控并进入清理，避免在未知状态下继续。errno=%d (%s)\n", tid, errno, strerror(errno));
                    g_running = 0;
                    /* Leave this thread stopped; cleanup restores its original state. */
                    continue;
                }
                if (r.pc != addr) {
                    /* Could be another pre-existing HW breakpoint. Do not eat its SIGTRAP. */
                    g_unexpected_stops++;
                    fprintf(stderr, "\n[提示] TID %d 硬件断点 PC=0x%llx 与目标 0x%llx 不同；保留并转发 SIGTRAP。\n",
                            tid, (unsigned long long)r.pc, (unsigned long long)addr);
                    deliver = sig;
                } else {
                    g_hw_hits++;
                    r.regs[ri] = val;
                    if (set_regs(tid, &r) == 0) {
                        g_hits++;
                        printf("\r硬件断点事件：%llu，寄存器写回成功：%llu（TID=%d，PC=0x%llx，X%d=0x%llx）   ",
                               g_hw_hits, g_hits, tid, (unsigned long long)r.pc, ri, (unsigned long long)val);
                        fflush(stdout);
                    } else {
                        g_write_failures++;
                        fprintf(stderr, "\n[错误] TID %d 写回寄存器失败：errno=%d (%s)\n", tid, errno, strerror(errno));
                    }
                    if (set_thread_break_enabled(t, 0) == -1) {
                        g_reenable_failures++;
                        t->monitoring = 0;
                        g_running = 0;
                        fprintf(stderr, "\n[严重警告] TID %d 暂停断点失败；不再单步或继续该线程，立即进入清理。errno=%d (%s)\n", tid, errno, strerror(errno));
                        continue;
                    }
                    t->stepping = 1;
                    if (ptrace(PTRACE_SINGLESTEP, tid, NULL, NULL) == 0) {
                        t->stopped = 0;
                        continue;
                    }
                    g_step_failures++;
                    t->stepping = 0;
                    t->monitoring = 0;
                    fprintf(stderr, "\n[错误] TID %d 单步执行失败：errno=%d (%s)；该线程停止监控，退出时恢复原状态。\n", tid, errno, strerror(errno));
                    /* Keep it stopped until cleanup restores the original HW state. */
                    g_running = 0;
                    continue;
                }
            }
            /* Do not suppress an unknown/unconfigured hardware SIGTRAP: it may
               belong to the target's original debugger state or signal handler. */
        }
        if (ptrace(PTRACE_CONT, tid, NULL, (void *)(intptr_t)deliver) == -1) {
            if (errno == ESRCH) {
                if (t) { t->attached = 0; t->stopped = 0; }
            } else {
                g_continue_failures++;
                fprintf(stderr, "\n[严重警告] TID %d 继续执行失败：errno=%d (%s)；停止监控并清理。\n", tid, errno, strerror(errno));
                g_running = 0;
                break;
            }
        } else if (t) {
            t->stopped = 0;
        }
    }
    puts("\n正在恢复原硬件断点状态并分离线程……");
    cleanup(ts, n);
    printf("\n========== RegHook v6.2 统计 =========="
           "\n识别到的硬件断点事件：%llu"
           "\n寄存器写回成功：%llu"
           "\n寄存器写回失败：%llu"
           "\n单步失败：%llu"
           "\n断点启用/恢复相关失败：%llu"
           "\n继续执行失败：%llu"
           "\n原断点状态恢复失败：%llu"
           "\n线程分离失败：%llu"
           "\n异常停止事件：%llu"
           "\n线程附加/停止失败：%llu"
           "\n断点安装失败线程：%llu"
           "\n寄存器上下文读取失败：%llu"
           "\n清理时无法确认线程停止：%llu"
           "\n启动时发现线程数：%llu"
           "\n成功附加/记录线程数：%llu"
           "\n成功恢复运行线程数：%llu\n",
           g_hw_hits, g_hits, g_write_failures, g_step_failures,
           g_reenable_failures, g_continue_failures, g_restore_failures,
           g_detach_failures, g_unexpected_stops, g_attach_failures, g_setup_failures,
           g_reg_read_failures, g_cleanup_stop_failures, g_threads_found,
           g_threads_attached, g_threads_resumed);
    return 0;
}
