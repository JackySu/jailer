# Jailer 管理员手册

适用对象：IT / 安全管理员（root 权限）

---

## 用户须知

### 1. 系统要求

| 项目 | 要求 |
|---|---|
| 内核版本 | Linux 5.11+（推荐 6.1+） |
| 内核配置 | `CONFIG_BPF_LSM=y`，`CONFIG_DEBUG_INFO_BTF=y` |
| 启动参数 | `lsm=` 列表中包含 `bpf` |
| cgroup | v2 unified hierarchy（挂载于 `/sys/fs/cgroup`） |
| 发行版 | Ubuntu 22.04+, Debian 12+, Rocky/Alma 9+, Fedora 35+, Arch |
| 不支持 | macOS, Windows, RHEL 7, CentOS 7, Debian 10 |

部署前执行自检：

```bash
jailerctl doctor
```

任何一项不满足，daemon 拒绝启动。

### 2. 架构

```
┌─────────────────────────────────────────────────┐
│ Kernel                                          │
│  BPF LSM hooks (file_open, bprm_check, ...)    │
│  BPF maps (role_flags, path_states, ...)        │
└────────────────────────┬────────────────────────┘
                         │ attach / populate
┌────────────────────────┴────────────────────────┐
│ bpfjailer-daemon (root)                         │
│  - 加载 BPF object                              │
│  - 读取 policy.json + drop-in + user_extensions │
│  - 监听 /run/bpfjailer/enrollment.sock          │
│  - 处理 EnrollSelf / Reload / Status 请求       │
│  - SIGHUP: 全量热重载 policy + user_extensions  │
└────────────────────────┬────────────────────────┘
                         │ unix socket (group: bpfjailer, mode 0660)
┌────────────────────────┴────────────────────────┐
│ jailerctl (unprivileged)                        │
│  - run: 请求 daemon 入笼当前进程                 │
│  - status: 查询 daemon 状态                      │
│  - enroll: 入笼指定 PID                         │
│  - reload: 触发 daemon 全量热重载               │
│  - audit: 查看 BPF LSM 拦截日志                 │
│  - effective-policy: 查看合并后的生效策略        │
│  - doctor / validate: 本地自检                   │
└─────────────────────────────────────────────────┘
```

### 3. 权限模型

- Daemon 以 root 运行（需要 `CAP_BPF` + `CAP_SYS_ADMIN`）。
- 用户通过 `bpfjailer` 组获得 socket 访问权限，无需 sudo。
- BPF LSM 决策基于 cgroup id，与进程 uid 无关。setuid 进程同样受约束。

```bash
groupadd bpfjailer
usermod -aG bpfjailer <username>
```

### 4. 配置

#### 文件位置

```
/etc/bpfjailer/policy.json        全局策略
/etc/bpfjailer/policy.d/*.json    drop-in 片段（按字典序合并）
~/.config/bpfjailer/policy.json   用户本地策略
```

#### 冲突规则

1. 全局 deny + 用户 allow → 全局赢，daemon 拒绝加载用户配置并报错
2. 用户可新增 deny（收紧），不可新增 allow（放宽）
3. 用户配置中出现任何违规字段 → 整份用户配置被拒绝，回退到纯全局策略
4. 全局规则可标记 `"lockdown": true`，锁定后用户不可覆盖该规则

#### 生效方式

修改全局 `policy.json`、drop-in 片段或用户 `user_extensions` 后，执行 `jailerctl reload` 或 `systemctl reload bpfjailer-daemon`（SIGHUP）即可生效，无需重启 daemon。

```bash
jailerctl reload
# 或
sudo systemctl reload bpfjailer-daemon
```

热重载流程：清空 BPF policy maps → 重读全局 policy + drop-in → 重载 user_extensions → 重新填充 BPF maps → 刷新 inode cache。已 enrolled 的进程保持 enrolled，新策略立即对其生效。

### 5. 日志

| 来源 | 内容 | 命令 |
|---|---|---|
| Daemon → journald | policy 加载、attach 状态、enrollment 事件 | `journalctl -u bpfjailer-daemon` |
| BPF audit → journald | 被拦截的操作（PID、role、路径/端口） | `journalctl -t bpfjailer-audit -f` |
| BPF trace pipe | BPF 程序内部调试输出（仅排查时开启） | `cat /sys/kernel/tracing/trace_pipe \| grep bpfjailer:` |

手动启动的 daemon 日志输出到 stderr，不经过 journald。生产环境使用 systemd unit。

### 6. 紧急停用

停用所有 BPF LSM enforcement，daemon 进程保持运行：

```bash
sudo touch /etc/bpfjailer/disabled
sudo systemctl reload bpfjailer-daemon
```

恢复：

```bash
sudo rm /etc/bpfjailer/disabled
sudo systemctl reload bpfjailer-daemon
```

机制：daemon 收到 SIGHUP 时检查 `/etc/bpfjailer/disabled` 是否存在。存在则 detach 所有 LSM hook；不存在则重新 attach。BPF object 和 map 保留在内存中，恢复无需重灌 policy。

daemon 启动时也检查该文件。可在部署阶段预置 disabled 文件，验证就绪后再删除启用。

### 7. 限制

- 不是整机 MAC（不替代 SELinux / AppArmor）
- 不检查文件内容（不是 DLP）
- 不防御恶意 root 用户（root 可卸载 BPF）
- audit log 为 best-effort，不保证不丢事件
- 与容器运行时正交，可叠加使用

---

## 后续章节（待补）

- §1 系统要求与兼容性矩阵
- §2 安装（`.deb` / `.rpm`）
- §3 全局 config 完整语法
- §4 故障排查手册

---

## 附录 A：策略配置示例

以下是一份面向 AI Code Agent 的完整策略配置，适用于限制代码生成工具的文件系统和网络访问：

```json
{
  "roles": {
    "code_agent": {
      "id": 100,
      "name": "code_agent",
      "flags": {
        "allow_file_access": true,
        "allow_network": true,
        "allow_exec": true,
        "require_signed_binary": false,
        "allow_setuid": false,
        "allow_ptrace": false,
        "allow_module_load": false,
        "allow_bpf_load": false,
        "require_proxy": false
      },
      "file_paths": [
        { "pattern": "/etc/shadow", "allow": false },
        { "pattern": "/etc/gshadow", "allow": false },
        { "pattern": "/etc/sudoers", "allow": false },
        { "pattern": "/etc/sudoers.d/", "allow": false },
        { "pattern": "/etc/ssh/", "allow": false },
        { "pattern": "/etc/ssl/private/", "allow": false },
        { "pattern": "/home/*/.ssh/", "allow": false },
        { "pattern": "/home/*/.aws/", "allow": false },
        { "pattern": "/home/*/.gnupg/", "allow": false },
        { "pattern": "/home/*/.netrc", "allow": false },
        { "pattern": "/home/*/.git-credentials", "allow": false },
        { "pattern": "/home/*/.kube/", "allow": false },
        { "pattern": "/home/*/.docker/config.json", "allow": false },
        { "pattern": "/home/*/.config/gcloud/", "allow": false },
        { "pattern": "/home/*/.azure/", "allow": false }
      ],
      "ip_rules": [
        { "cidr": "169.254.169.254/32", "direction": "connect", "allow": false }
      ],
      "domain_rules": [],
      "network_rules": [],
      "execution_rules": [],
      "proxy": null
    }
  },
  "pods": [],
  "exec_enrollments": [],
  "cgroup_enrollments": [
    {
      "cgroup_path": "/sys/fs/cgroup/bpfjailer/code-agent",
      "pod_id": 5000,
      "role": "code_agent"
    }
  ]
}
```

#### 设计说明

| 配置项 | 说明 |
|---|---|
| `allow_file_access: true` | 允许文件访问，但通过 `file_paths` deny 列表限制敏感路径 |
| `allow_setuid: false` | 禁止提权 |
| `allow_ptrace: false` | 禁止调试其他进程 |
| `allow_module_load: false` | 禁止加载内核模块 |
| `allow_bpf_load: false` | 禁止加载 BPF 程序 |
| `file_paths` | 屏蔽凭据文件（SSH key、cloud credentials、GPG 等） |
| `ip_rules` | 屏蔽云 metadata endpoint（防止 SSRF 获取 IAM token） |
| `cgroup_enrollments` | 通过 cgroup 自动 enroll，无需手动操作 |

#### 查看生效策略

用户可通过以下命令查看合并后的完整策略（含 drop-in 和 user_extensions）：

```bash
jailerctl effective-policy
```

输出会标注每条规则的来源（`base` / `user`）以及是否被 lockdown。
