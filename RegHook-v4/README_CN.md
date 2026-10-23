# RegHook v4（ARM64 / ptrace 硬件执行断点）

> 实验性诊断版本，尚未在 MIX 4 / Android 5.4.233-qgki 真机上验证。仅用于你有权调试的自建测试进程；错误的寄存器写入可能导致目标进程异常。

## v4 修正

v3 在 `PTRACE_SETREGSET(NT_ARM_HW_BREAK)` 中始终传入整个 `user_hwdebug_state`（最多 16 个槽位）。Linux ARM64 的 `hw_break_set()` 会按传入长度逐个处理槽位；整块写入可能触碰超过设备实际硬件断点槽位数量的条目并返回 `ENOSPC`。

v4 将每次写入限制到当前要修改的槽位为止：`iov_len = offsetof(dbg_regs) + (slot + 1) * sizeof(slot)`，同时打印 `dbg_info`、报告槽位数、`errno` 和写入长度。恢复时也只恢复本程序实际触碰的槽位前缀。

## 使用建议

1. 用 GitHub Actions 构建。
2. 先在自建的简单 ARM64 测试进程上验证，不要直接在重要游戏进程上试。
3. 保存完整日志，重点看 `[诊断]`、`errno`、`dbg_info` 和是否成功启用。
4. `PTRACE_SETREGSET` 成功不等于断点一定能命中；命中后的单步和信号行为仍需真机验证。

## 限制

- 不自动跟踪之后新建的线程。
- 厂商内核可能对调试寄存器和信号行为有差异。
- 不能保证目标程序在寄存器被修改后继续正常运行。

参考 Linux ARM64 `arch/arm64/kernel/ptrace.c` 的 `hw_break_set()`：
https://code.googlesource.com/linux/torvalds/linux/+/9f7853d7609d59172eecfc5e7ccf503bc1b690bd/arch/arm64/kernel/ptrace.c
