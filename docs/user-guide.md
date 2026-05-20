# Jailer 用户手册

适用对象：使用 code-agent 的开发者

---

## 用户须知

### 1. 功能概述

Jailer 对 code-agent 进程组施加文件和网络访问限制。被限制的操作返回 `Permission denied`。你自身的 shell 和其他进程不受影响。

受限范围（由 IT 全局策略定义，以下为默认配置）：

| 类别 | 被拦截的访问 |
|---|---|
| 凭证文件 | `/home/*/.ssh/`, `/home/*/.aws/`, `/home/*/.gnupg/`, `/home/*/.kube/`, `/home/*/.docker/config.json`, `/home/*/.git-credentials`, `/home/*/.netrc` |
| 系统敏感文件 | `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers`, `/etc/ssh/`, `/etc/ssl/private/` |
| 云凭证 | `/home/*/.config/gcloud/`, `/home/*/.azure/` |
| 网络 | 云元数据端点 `169.254.169.254` |

不受限：`/etc/passwd`、`/etc/hostname`、项目工作目录、`/tmp`、公网访问（除上述 IP 外）。

### 2. 使用方式

#### 透明模式（默认）

code-agent 启动时自动入笼，无需操作。

#### 手动模式

```bash
jailerctl run                        # 进入受限 shell
jailerctl run -- python3 script.py   # 在沙箱中执行指定命令
exit                                 # 退出受限 shell
```

不需要 sudo。需要用户在 `bpfjailer` 组中（IT 已配置）。

### 3. 本地配置

路径：`~/.config/bpfjailer/policy.json`

允许操作：新增 deny 规则（收紧限制）。

禁止操作：新增 allow 规则、修改全局 deny 为 allow、修改 lockdown 字段。违反时 daemon 拒绝加载整份本地配置并报错。

示例：

```json
{
  "user_extensions": [
    { "pattern": "/home/me/notes/private/", "allow": false }
  ]
}
```

修改后执行：

```bash
jailerctl reload
```

### 4. 查看生效策略

```bash
jailerctl effective-policy
```

输出标注每条规则来源（`base` / `user`），lockdown 规则标记 `[LOCKED]`。

### 5. 排查被拦截的操作

```bash
jailerctl audit --me --since 5min
```

输出包含：PID、被拦截的路径或端口、命中的规则。

### 6. 本地配置与全局配置冲突

全局策略优先级高于本地配置，无例外。

遇到冲突时：

1. 执行 `jailerctl effective-policy` 获取当前生效规则
2. 携带输出联系 IT 处理

### 7. 常用命令

| 命令 | 用途 |
|---|---|
| `jailerctl run` | 进入受限 shell |
| `jailerctl run -- <cmd>` | 在沙箱中执行命令 |
| `jailerctl status` | 查看 daemon 状态（是否 enforcing、hook 数、role 列表） |
| `jailerctl enroll --role <name>` | 将当前进程入笼到指定 role |
| `jailerctl effective-policy` | 查看合并后的生效策略（含来源标注） |
| `jailerctl reload` | 重新加载策略和 user_extensions |
| `jailerctl audit --me --since 5min` | 查看最近被拦截的操作 |
| `jailerctl audit -f` | 实时跟踪审计事件 |
| `jailerctl doctor` | 系统状态自检 |
| `jailerctl validate <file>` | 校验策略文件语法 |

---

## 后续章节（待补）

- §1 本地配置完整语法
- §2 常见错误对照表
