# dsh-plugin-vet

DeepSeek Harness 插件：对已安装的**第三方插件**做恶意行为启发式扫描 + 可选运行时绊线。

## 威胁模型（先读这个）

DSH 插件在 harness 进程内执行，拥有完整权限。因此本插件**不是安全边界**——它是**启发式绊线**（类似杀毒软件）：静态扫描插件源码，命中可疑模式（网络外传、凭据访问、混淆、持久化）就按权重打分并报告，**从不执行插件代码**，也**不拦截**（拦截会误伤正常插件）。

真正的根治方案应由 harness 提供"挂载前扫描钩子"——本插件是该思路的独立原型。

## 功能

| 能力 | 说明 |
|---|---|
| `plugin_vet` 工具 / `/plugin-vet` 命令 | 扫描 `$DSH_HOME/profiles/*/node_modules` 下所有 `dsh-plugin-*`（含 `@scope/dsh-plugin-*`）第三方包，输出每个包的风险等级 + 命中位置（文件:行号） |
| 官方豁免 | `@deepseek-ai/*` 自动豁免（它们本身含 fetch/spawn 等正常行为） |
| 运行时绊线（可选） | `config.monitor: true` 时包装 `subprocess.spawn`，对可疑命令（外传网络、读 `/proc/<pid>/environ`）记警告日志；只记不改 |

## 扫描规则（启发式）

网络外传（fetch/HTTP 字面量/裸 socket/ngrok/webhook.site 等中继域名/硬编码 IP）、凭据访问（`process.env.*KEY*`、`.credentials.yaml`、`.env`、`/proc/*/environ`）、代码执行与混淆（`eval`/`new Function`/大段 base64/`fromCharCode`）、持久化（schtasks/开机启动/authorized_keys/cron）、读会话日志、install 生命周期脚本。

权重累加：**SAFE(0) / LOW(1-4) / MEDIUM(5-9) / HIGH(≥10)**。

## 安装

```bash
dsh plugin --profile web add dsh-plugin-vet
```

挂载（profile `cordis.patch.yml`）：

```yaml
- id: plugin-vet
  name: dsh-plugin-vet
  config:
    # roots 缺省 = $DSH_HOME/profiles/*/node_modules
    # monitor: true  # 开启运行时子进程绊线（只记日志）
    # allowlist: [dsh-plugin-security-audit, dsh-plugin-credential-guard]
    #   # 白名单：可信插件（如你自己的安全插件——它们规则里引用密钥路径，启发式必然高分）
```

## 使用

- 模型工具：`plugin_vet`
- 斜杠命令：`/plugin-vet`

示例输出：

```
# Plugin vet — 4 third-party plugin(s) scanned
safe=2 low=1 medium=1 high=0

[LOW] dsh-plugin-search-gate@0.1.0 (score 3)
    - network-http: contains HTTP(S) URL literals @ lib/index.js:12
    ...

> heuristic scan only: a clean result is not a security guarantee
```

## 开发

```bash
npm test   # node --test，零依赖
```

## 诚实边界

- 启发式扫描：恶意代码伪装成正常写法仍可能漏过；干净结果 ≠ 安全保证；
- **已知误报类**：安全类插件（如 credential-guard / security-audit）的规则里会引用密钥路径、外传域名，启发式扫描必然高分——这是特征不是 bug，用 `allowlist` 白名单处理；
- 静态扫描不覆盖"运行时才下载执行"的载荷；
- 绊线只记录不阻断；官方豁免按包名判断，不校验发布者可信度。
