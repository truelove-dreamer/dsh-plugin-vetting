/**
 * Static heuristic rules for plugin vetting.
 *
 * Two threat categories:
 *  - "malicious": deliberate abuse (exfiltration, credential theft,
 *    obfuscation, persistence). Weights sum into the risk score.
 *  - "sloppy": not malicious, but accidentally touches high-privilege
 *    paths (home-dir reads built by string concatenation, broad recursion
 *    over the home directory). Reported as "suggest narrowing" advisories,
 *    not as suspicion.
 *
 * Every rule is a regex matched against plugin source text. A hit means
 * "inspect this", not "this plugin is malware". Official harness packages
 * (@deepseek-ai/*) are exempt by name, and the scanner never executes
 * plugin code.
 *
 * @module dsh-plugin-vetting/rules
 */

export const RULES = [
	// ── malicious: deliberate abuse ────────────────────────────────────────
	{ id: "network-fetch", category: "malicious", weight: 3, pattern: /\bfetch\s*\(/, note: "makes fetch network requests", noteZh: "发起 fetch 网络请求" },
	{ id: "network-http", category: "malicious", weight: 4, pattern: /https?:\/\//, note: "contains HTTP(S) URL literals", noteZh: "包含 HTTP(S) URL 字面量" },
	{ id: "network-socket", category: "malicious", weight: 5, pattern: /\bnet\.connect\b|\bdgram\b|\bWebSocket\b|\bhttp\.request\b/, note: "opens raw sockets / non-fetch HTTP", noteZh: "打开原始 socket / 非 fetch 的 HTTP" },
	{ id: "exfil-hosts", category: "malicious", weight: 5, pattern: /ngrok|webhook\.site|requestbin|pastebin|api\.telegram\.org|discord(app)?\.com\/api\/webhooks/, note: "references known exfiltration / relay hosts", noteZh: "引用已知外传/中继域名" },
	{ id: "ip-literal", category: "malicious", weight: 2, pattern: /(?:https?:\/\/|["'\s])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, note: "hardcoded IPv4 address", noteZh: "硬编码 IPv4 地址" },
	{ id: "credential-env", category: "malicious", weight: 4, pattern: /process\.env\.[A-Z_]*(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)/i, note: "reads credential-like environment variables", noteZh: "读取凭据类环境变量" },
	{ id: "credential-file", category: "malicious", weight: 5, pattern: /\.credentials\.ya?ml|[\\/'"]\.env\b|id_rsa|id_ed25519|\.netrc|\.pgpass/, note: "touches credential / secret files", noteZh: "触及凭据/密钥文件" },
	{ id: "proc-environ", category: "malicious", weight: 5, pattern: /\/proc\/\d+\/environ|\/proc\/self\/environ/, note: "reads process environments", noteZh: "读取进程环境(/proc/*/environ)" },
	{ id: "session-log-read", category: "malicious", weight: 3, pattern: /\.dsh[/\\]sessions|session\.jsonl|\.dsh[/\\]storages/, note: "reads harness session logs / storages", noteZh: "读取 harness 会话日志/存储" },
	{ id: "exec", category: "malicious", weight: 4, pattern: /child_process|\bspawn\b|\bexec(Sync)?\s*\(/, note: "spawns child processes", noteZh: "启动子进程" },
	{ id: "eval", category: "malicious", weight: 4, requiresReview: true, pattern: /\beval\s*\(|new Function\s*\(|vm\.runInNewContext\s*\(|Function\s*\(\s*["'`]/, note: "dynamic code execution — static scan cannot see what runs here; requires manual review", noteZh: "动态执行代码——静态扫描看不到其内容，需人工确认" },
	{ id: "base64-payload", category: "malicious", weight: 3, pattern: /[A-Za-z0-9+/]{60,}={0,2}/, note: "large base64 blob (possible payload)", noteZh: "大段 base64（可能是载荷）" },
	{ id: "persistence", category: "malicious", weight: 5, pattern: /schtasks|\bStartup\b|HKCU|\.bashrc|\.profile|\.zshrc|authorized_keys|\bcron\b/, note: "persistence mechanisms", noteZh: "持久化机制" },
	{ id: "install-script", category: "malicious", weight: 2, pattern: /"(pre|post)?install|prepare|prepublishOnly"\s*:/, note: "lifecycle script (install/prepare/prepublishOnly run on install, including git deps)", noteZh: "生命周期脚本（install/prepare/prepublishOnly，git 依赖安装时也会执行）" },
	{ id: "obfuscation", category: "malicious", weight: 4, pattern: /String\.fromCharCode\s*\(|\\\\x[0-9a-fA-F]{2}|fromCharCode/, note: "obfuscation technique", noteZh: "混淆技术" },

	// ── sloppy: not malicious, but overly broad privilege use ─────────────
	{ id: "sloppy-home-read", category: "sloppy", weight: 0, pattern: /process\.env\.(HOME|USERPROFILE)|\bos\.homedir\(\)|~\/\.(ssh|aws|config|gnupg)/, note: "reads under the user home / secret dirs with broad patterns — suggest narrowing to explicit paths", noteZh: "以宽泛模式读取用户主目录/密钥目录——建议收窄到显式路径" },
	{ id: "sloppy-concat-path", category: "sloppy", weight: 0, pattern: /read(File|dir)Sync\s*\(\s*[^)]*(HOME|homedir|USERPROFILE)\s*\+/, note: "builds file paths by concatenating home/env strings — suggest explicit path joins", noteZh: "用字符串拼接主目录/环境变量构造路径——建议显式 join" },
	{ id: "sloppy-recursive-home", category: "sloppy", weight: 0, pattern: /readdirSync\s*\(\s*(process\.env\.HOME|process\.env\.USERPROFILE|os\.homedir\s*\(\s*\))/, note: "recursively enumerates the home directory — suggest a narrow target", noteZh: "递归枚举主目录——建议限定目标" }
];

/** Risk classification from a summed malicious-rule score. */
export function classify(score, thresholds = { medium: 5, high: 10 }) {
	if (score >= thresholds.high) return "HIGH";
	if (score >= thresholds.medium) return "MEDIUM";
	if (score > 0) return "LOW";
	return "SAFE";
}

/** Whether a package name is part of the official harness install. */
export function isOfficial(packageName) {
	return packageName === "@deepseek-ai/dsh" || packageName.startsWith("@deepseek-ai/");
}

/** Whether a directory name looks like a third-party dsh plugin package. */
export function isPluginPackage(packageName) {
	if (isOfficial(packageName)) return false;
	if (packageName.startsWith("dsh-plugin-")) return true;
	if (/^@.+\/dsh-plugin-/.test(packageName)) return true;
	return false;
}
