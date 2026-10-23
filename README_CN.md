# RegHook v1 — GitHub Actions 构建版

本仓库加入 GitHub Actions 工作流，可在 GitHub 云端构建 Android ARM64（AArch64）可执行文件。

## 如何使用

1. 将 ZIP 解压后，把其中全部文件上传到一个 GitHub 仓库。
2. 确保 `.github/workflows/build.yml` 路径没有被改名。
3. 推送代码到 GitHub，或打开仓库的 **Actions** 页面，选择 **Build RegHook ARM64**，再点 **Run workflow**。
4. 打开完成的 workflow 运行记录，在 **Artifacts** 区域下载 `RegHook-android-arm64`。
5. 解压后会有 `reghook-arm64`，可复制到已 Root 的 Android ARM64 设备进行进一步测试。

## 工作流做什么

- 使用 Android NDK r27c。
- 以 `aarch64-linux-android24-clang` 编译。
- 检查输出文件类型及 ELF 头。
- 打包二进制、源码、说明和 SHA-256 校验文件。
- 上传构建产物，保留 30 天。

## 重要限制

**GitHub Actions 构建成功只代表代码通过编译，不代表硬件断点和寄存器修改功能已在 Android 设备上验证。** 当前 RegHook 仍是实验性原型；特别是 `perf_event_open`、异步 SIGTRAP、跨进程目标线程寄存器写回及恢复执行机制都需要针对目标内核继续实现和实测。

如构建因 NDK 头文件或 Android bionic API 差异失败，请查看 Actions 日志中的第一条编译错误，再按该错误修复；不要把“workflow 已配置”理解成“已确认能够成功构建”。
