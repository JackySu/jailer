# icb-sandbox 集成指南

面向 icb-agent 用户的沙箱集成文档。

## 概述

icb-sandbox 是 icb-agent 的内核级沙箱子系统。它通过 Linux BPF LSM 在内核层面强制执行文件访问、网络出口等安全策略，防止 AI agent 在执行工具调用时访问敏感资源（SSH 密钥、云凭证、密码文件等）。

icb-sandbox 在操作系统层面拦截 syscall，即使 agent 被 prompt injection 攻击也无法绕过。

## 安装

通过 AppImage 一键安装（包含 icb-agent + sandbox 全套组件）：

```bash
chmod +x icb-installer-*.AppImage
sudo ./icb-installer-*.AppImage install
```

安装过程会：
1. 检查内核是否满足要求（BTF + BPF LSM）
2. 询问 icb-agent 安装路径（默认 `/usr/bin/icb-agent`）
3. 安装 daemon、CLI、BPF object 到系统目录
4. 生成 `/etc/icb/sandbox/policy.toml` 并自动添加 icb-agent 的 exec_enrollment
5. 启动 `icb-sandboxd.service`

安装完成后，icb-agent 一旦被执行就会自动进入沙箱（通过 exec_enrollment 机制）。

## 快速验证

```bash
# 检查 daemon 状态
icb-sandbox-ctl status

# 在沙箱中尝试读取 SSH 密钥
icb-sandbox-ctl run -- cat ~/.ssh/id_rsa
# 预期输出: cat: /home/<user>/.ssh/id_rsa: Permission denied

# 在沙箱中正常使用 git（exec_enrollment 自动切换到 git_agent 角色）
icb-sandbox-ctl run -- git pull
# 预期输出: 正常拉取（git_agent 角色允许访问 ~/.ssh）
```

## 工作原理

### exec_enrollment 自动入笼

安装时，AppImage 在 `/etc/icb/sandbox/policy.toml` 中为 icb-agent 添加了 exec_enrollment 规则：

```toml
[[exec_enrollments]]
executable_path = "/usr/bin/icb-agent"
pod_id = 5010
role = "code_agent"
```

这意味着：任何进程 exec icb-agent 时，BPF `bprm_check_security` hook 自动将其放入 `code_agent` 角色的沙箱。icb-agent 的所有子进程（bash tool 等）通过 cgroup 继承自动受限。

### cgroup 继承

```
icb-agent (exec → 自动入笼 code_agent)
    │
    ├─ bash -c "cat /etc/shadow"     → EACCES (继承 code_agent)
    ├─ bash -c "git push"
    │    └─ git (exec)               → exec_enrollment → git_agent
    │         └─ ssh git@github.com  → 允许 ~/.ssh
    └─ bash -c "docker build ."
         └─ docker (exec)            → exec_enrollment → docker_agent
              (允许 ~/.docker/config.json)
```

### exec_enrollment 覆盖

当子进程 exec 特定二进制时，BPF hook 自动切换到对应角色：

| 二进制 | 目标角色 | 额外允许 |
|--------|----------|----------|
| `/usr/bin/git` | git_agent | ~/.ssh/, ~/.git-credentials |
| `/usr/bin/ssh` | git_agent | 同上 |
| `/usr/bin/docker` | docker_agent | ~/.docker/config.json |
| `/usr/bin/kubectl` | kubectl_agent | ~/.kube/ |

## 策略配置

策略文件使用 TOML 格式，位于 `/etc/icb/sandbox/policy.toml`。

核心结构：

```toml
# 定义角色
[roles.code_agent]
id = 100
name = "code_agent"

[roles.code_agent.flags]
allow_file_access = true
allow_network = true
allow_exec = true
allow_setuid = false
allow_ptrace = false
allow_module_load = false
allow_bpf_load = false

# 文件访问 deny 规则
[[roles.code_agent.file_paths]]
pattern = "/home/*/.ssh/"
allow = false

# IP 规则（阻止 IMDS）
[[roles.code_agent.ip_rules]]
cidr = "169.254.169.254/32"
direction = "connect"
allow = false

# exec_enrollment: 二进制执行时自动切换角色
[[exec_enrollments]]
executable_path = "/usr/bin/icb-agent"
pod_id = 5010
role = "code_agent"

[[exec_enrollments]]
executable_path = "/usr/bin/git"
pod_id = 5001
role = "git_agent"
```

修改后执行 `icb-sandbox-ctl reload` 热加载。

## 用户自定义规则

用户可以在 `~/.config/icb/sandbox/policy.toml` 中添加额外的 deny 规则：

```toml
[[user_extensions]]
pattern = "/home/me/private-project/"
allow = false

[[user_extensions]]
pattern = "/home/me/.secrets/"
allow = false
```

限制：
- 只能添加 deny 规则（`allow = false`）
- 不能覆盖 IT 标记为 `lockdown = true` 的规则
- 修改后执行 `icb-sandbox-ctl reload` 生效

查看当前生效的完整策略：

```bash
icb-sandbox-ctl effective-policy
```

## 升级与卸载

```bash
# 检查版本
./icb-installer-*.AppImage status

# 升级（保留现有 policy.toml）
sudo ./icb-installer-*.AppImage upgrade

# 卸载（保留配置）
sudo ./icb-installer-*.AppImage uninstall

# 卸载（清除所有配置）
sudo ./icb-installer-*.AppImage uninstall --purge
```

## 常见问题

### git push 失败 (Permission denied)

确认 exec_enrollment 包含 git 和 ssh：

```bash
icb-sandbox-ctl effective-policy | grep -A5 git_agent
```

如果 git 使用的 ssh 路径不在 exec_enrollment 中（如 `/usr/lib/ssh/ssh`），需要在 policy.toml 中添加。

### docker build 失败

确认 docker 二进制路径匹配 exec_enrollment：

```bash
which docker  # 确认路径是 /usr/bin/docker
```

如果 docker 安装在非标准路径，更新 `policy.toml` 中的 `exec_enrollments`。

### 临时禁用沙箱

```bash
sudo touch /etc/icb/sandbox/disabled
sudo systemctl reload icb-sandboxd
```

恢复：

```bash
sudo rm /etc/icb/sandbox/disabled
sudo systemctl reload icb-sandboxd
```

### 查看被拦截的操作

```bash
icb-sandbox-ctl audit --me --since 5min
icb-sandbox-ctl audit -f  # 实时跟踪
```
