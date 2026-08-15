# dsh-plugin-vetting

DeepSeek Harness 插件：对已安装的**第三方插件**做恶意行为启发式扫描 + 误伤（高权限误用）提示 + 可选运行时绊线。

## 威胁模型（先读这个）

DSH 插件在 harness 进程内执行，拥有完整权限。因此本插件**不是安全边界**——它是**启发式绊线**（类似杀毒软件）：静态扫描插件源码，命中可疑模式就报告，**从不执行插件代码**，**不拦截**（拦截会误伤正常插件）。

**三类威胁，两种输出：**

| 威胁 | 输出 | 含义 |
|---|---|---|
| **恶意**（外传凭据、eval、持久化） | risk 分数 → SAFE/LOW/MEDIUM/HIGH | 蓄意滥用，需人工核实 |
| **误伤**（非恶意，但高权限路径写得太糙） | `suggest narrowing` 建议区 | 不扣分、不标可疑，只建议收窄权限 |
| **运行时动态加载**（下载后 eval、远端模块） | 文档声明 + `[REVIEW]` 标记 | 静态扫描看不到，**不在扫描范围** |

**fail-closed 视角**：任何命中 `eval` / `new Function` / `vm.runInNewContext` 的插件，**无论总分多少**都标 `[REVIEW: dynamic code execution present]`——eval 是静态扫描最大的盲区，它的存在本身就应降级信任，而不是等凑够分数才 HIGH。

真正的根治方案应由 harness 提供"挂载前扫描钩子"——本插件是该思路的独立原型。

## 功能

| 能力 | 说明 |
|---|---|
| `plugin_vet` 工具 / `/plugin-vet` 命令 | 扫 `$DSH_HOME/profiles/*/node_modules` 下所有 `dsh-plugin-*`（含 `@scope/dsh-plugin-*`）第三方包 |
| 恶意规则（15 条） | 网络外传、凭据访问、代码执行/混淆、持久化、读会话日志、生命周期脚本（**含 install/prepare/prepublishOnly**——git 依赖安装时 prepare 也会执行） |
| 误伤规则（3 条） | home 目录宽松读取、字符串拼接路径、递归遍历 home——标为"建议收窄"而非可疑 |
| 传递依赖 | 统计声明依赖数 + 就地扫描嵌套 `node_modules/*` 的生命周期脚本，报告"N 个未检查" |
| `[REVIEW]` 标记 | eval/new Function 命中即降级信任，不看总分 |
| **覆盖范围报告** | 每个包报告"扫了 N 个文件、M 行代码、X 个依赖/脚本"，让边界显式可见 |
| **运行时表面** | 每个包报告 child_process / fetch / eval / socket 的**出现次数**——静态能告诉你插件运行时能触及哪些危险原语 |
| **官方包哈希基线**（默认开） | `@deepseek-ai/*` 豁免的同时记录内容哈希基线（`$DSH_HOME/.dsh-plugin-vetting/baseline.json`）；安装包与基线不一致 → 豁免自动失效并报警（供应链投毒检测）——从"信任名字"变"信任内容" |
| 运行时绊线（可选，仅日志） | `config.monitor: true` 时监控 **harness 的 `ctx.subprocess` 通道**，可疑命令记警告日志；**只记不改** |
| 官方豁免 | `@deepseek-ai/*` 自动豁免（但见哈希基线） |
| 白名单 | `config.allowlist` 放行可信插件 |

## 安装

包已声明 `dsh.bundle` manifest（根目录 `cordis.patch.yml`），一条命令自动挂载：

```bash
dsh plugin --profile web add dsh-plugin-vetting
```

手动挂载（可选，等价写法）：

```yaml
- insert:
    - id: plugin-vet
      name: dsh-plugin-vetting
      config:
        # monitor: true  # 可选：运行时子进程绊线（只记日志）
        # allowlist: [dsh-plugin-security-audit]
        #   # 白名单：可信插件（安全插件规则里引用密钥路径，启发式必然高分）
```

## 使用

- 模型工具：`plugin_vet`
- 斜杠命令：`/plugin-vet`

示例输出：

```
# Plugin vet — 2 third-party plugin(s) scanned
safe=1 low=0 medium=0 high=1

[HIGH] dsh-plugin-some-plugin@1.2.0 (score 12)
    - network-fetch: makes fetch network requests @ lib/index.js:8
    - eval: dynamic code execution — static scan cannot see what runs here; requires manual review @ lib/index.js:21 [REVIEW]
    suggest narrowing (not suspicion):
      - sloppy-home-read: reads under the user home with broad patterns @ lib/index.js:4
    deps: 3 declared, 2 nested scanned, 1 unchecked
      - nested dep evil-dep has lifecycle scripts: postinstall

> heuristic scan only: a clean result is not a security guarantee
> runtime-dynamic code (downloaded then eval'd, remote modules) is NOT in scope — static scan cannot see it
```

## 开发

```bash
npm test   # node --test，零依赖
```

## 诚实边界

- 启发式扫描：恶意代码伪装成正常写法仍可能漏过；干净结果 ≠ 安全保证；
- **运行时动态加载的代码（下载后 eval、require 远端模块）不在静态扫描范围**——不要因扫描通过就放松警惕；
- **本插件不做"插件进程内行为门禁"**：插件在 harness 进程内直接调 `child_process`/`fetch`/`eval` 不经过 harness 的 `ctx.subprocess`，绊线看不到、也拦不住。要真正门禁这类行为，需要 harness 把插件跑在**受控执行环境**（受限 worker/VM）里——那是架构级能力，超出单个插件范围，本插件明确不假装提供；
- **绊线只监控 harness 子进程通道且只记日志**，从不阻断（静态置信度不足以拦停，误伤比漏检更危险）；
- **已知误报类**：安全类插件（如 credential-guard / security-audit）的规则里会引用密钥路径、外传域名，启发式必然高分——用 `allowlist` 白名单处理；
- 传递依赖只做**就地**扫描（包内嵌套 node_modules）+ 声明计数；提升到宿主 node_modules 的依赖不会逐个深扫，未检查数如实报告；
- 官方豁免按包名判断，但内容哈希基线让"信任名字"变成"信任内容"（不一致即报警）。
