/**
 * Static heuristic rules for plugin vetting.
 *
 * Every rule is a regex matched against plugin source text. Rules are honest
 * heuristics: a hit means "inspect this", not "this plugin is malware".
 * Official harness packages (@deepseek-ai/*) are exempt by name, and the
 * scanner never executes plugin code.
 *
 * @module dsh-plugin-vet/rules
 */

export const RULES = [
	{ id: "network-fetch", weight: 3, pattern: /\bfetch\s*\(/, note: "makes fetch network requests" },
	{ id: "network-http", weight: 4, pattern: /https?:\/\//, note: "contains HTTP(S) URL literals" },
	{ id: "network-socket", weight: 5, pattern: /\bnet\.connect\b|\bdgram\b|\bWebSocket\b|\bhttp\.request\b/, note: "opens raw sockets / non-fetch HTTP" },
	{ id: "exfil-hosts", weight: 5, pattern: /ngrok|webhook\.site|requestbin|pastebin|api\.telegram\.org|discord(app)?\.com\/api\/webhooks/, note: "references known exfiltration / relay hosts" },
	{ id: "ip-literal", weight: 2, pattern: /(?:https?:\/\/|["'\s])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, note: "hardcoded IPv4 address" },
	{ id: "credential-env", weight: 4, pattern: /process\.env\.[A-Z_]*(KEY|SECRET|TOKEN|PASSWORD|CREDENTIAL)/i, note: "reads credential-like environment variables" },
	{ id: "credential-file", weight: 5, pattern: /\.credentials\.ya?ml|\.env\b|id_rsa|id_ed25519|\.netrc|\.pgpass/, note: "touches credential / secret files" },
	{ id: "proc-environ", weight: 5, pattern: /\/proc\/\d+\/environ|\/proc\/self\/environ/, note: "reads process environments" },
	{ id: "session-log-read", weight: 3, pattern: /\.dsh[/\\]sessions|session\.jsonl|\.dsh[/\\]storages/, note: "reads harness session logs / storages" },
	{ id: "exec", weight: 4, pattern: /child_process|\bspawn\b|\bexec(Sync)?\s*\(/, note: "spawns child processes" },
	{ id: "eval", weight: 4, pattern: /\beval\s*\(|new Function\s*\(|vm\.runInNewContext\s*\(|Function\s*\(\s*["'`]/, note: "dynamic code execution" },
	{ id: "base64-payload", weight: 3, pattern: /[A-Za-z0-9+/]{60,}={0,2}/, note: "large base64 blob (possible payload)" },
	{ id: "persistence", weight: 5, pattern: /schtasks|\bStartup\b|HKCU|\.bashrc|\.profile|\.zshrc|authorized_keys|\bcron\b/, note: "persistence mechanisms" },
	{ id: "install-script", weight: 2, pattern: /"(pre|post)?install"\s*:/, note: "install lifecycle script" },
	{ id: "obfuscation", weight: 4, pattern: /String\.fromCharCode\s*\(|\\\\x[0-9a-fA-F]{2}|fromCharCode/, note: "obfuscation technique" }
];

/** Risk classification from a summed score. */
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
