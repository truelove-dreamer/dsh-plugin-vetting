/**
 * @deepseek-ai/dsh-plugin-vet — a DeepSeek Harness host plugin that vets
 * installed third-party plugins for malicious behavior.
 *
 * Threat model: a plugin runs inside the harness process with full
 * privileges, so this scanner is a HEURISTIC TRIPWIRE, not a security
 * boundary — like antivirus, it flags suspicious patterns for a human to
 * review, and it never executes plugin code.
 *
 * Registers:
 *  - the `plugin_vet` model tool, and
 *  - the `/plugin-vet` human command (when `commands` is mounted).
 *
 * Optional runtime tripwire (config `monitor: true`): wraps
 * `ctx.subprocess.spawn` and logs a warning when a spawned command matches
 * exfiltration-style patterns (network to external hosts, reading
 * /proc/<pid>/environ, ...). LOG-ONLY, and it watches the HARNESS
 * subprocess channel only — a plugin calling `child_process` directly
 * inside the harness process does NOT go through `ctx.subprocess`, so this
 * tripwire cannot see it. Gating plugin-internal behavior requires the
 * harness to run plugins in a controlled execution environment; that is
 * architecture work beyond a single plugin, and it is NOT attempted here.
 *
 * Optional official-package content-hash baseline (config
 * `hashOfficial`, default true): @deepseek-ai/* packages are exempt from
 * the heuristic rules, but their content is hashed and compared against a
 * persisted baseline ($DSH_HOME/.dsh-plugin-vetting/baseline.json). A
 * mismatch revokes the exemption and reports a possible supply-chain
 * tampering warning — trust moves from the name to the content.
 *
 * Mount it in a profile patch or agent preset:
 *   - id: plugin-vet
 *     name: dsh-plugin-vet
 *     config:
 *       roots: [ ... ]        # package-container dirs; defaults below
 *       monitor: false        # enable the subprocess tripwire (log only)
 *       hashOfficial: true    # official-package content-hash baseline
 *
 * @module dsh-plugin-vet
 */
import { homedir } from "node:os";
import { existsSync, readdirSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { runVet } from "./scan.js";

/** Stable Cordis plugin name. */
const name = "plugin-vet";
/** Hard dependency: the tool registry. */
const inject = ["tools"];

/** Resolve the harness home the same way the deployment does. */
function resolveDshHome() {
	return process.env.DSH_HOME ?? join(homedir(), ".dsh");
}

/** Default scan roots: every profile's node_modules under the harness home. */
function defaultRoots() {
	const profiles = join(resolveDshHome(), "profiles");
	const roots = [];
	if (existsSync(profiles)) {
		for (const entry of readdirSync(profiles, { withFileTypes: true })) {
			if (!entry.isDirectory()) continue;
			const nm = join(profiles, entry.name, "node_modules");
			if (existsSync(nm)) roots.push(nm);
		}
	}
	return roots;
}

/** Render one package row into text. */
function renderPackage(p) {
	const lines = [];
	const tag = p.allowlisted === true ? "ALLOWED" : p.risk;
	lines.push(`[${tag}] ${p.name}@${p.version} (score ${p.score})${p.needsReview === true ? " [REVIEW: dynamic code execution present]" : ""}`);
	for (const f of p.findings.slice(0, 10)) {
		lines.push(`    - ${f.id}: ${f.note} @ ${f.file}:${f.line}`);
	}
	if (p.findings.length > 10) lines.push(`    ... and ${p.findings.length - 10} more`);
	if (p.findings.length === 0) lines.push("    (no malicious-pattern hits)");
	if (p.sloppyFindings !== undefined && p.sloppyFindings.length > 0) {
		lines.push(`    suggest narrowing (not suspicion):`);
		for (const f of p.sloppyFindings.slice(0, 5)) {
			lines.push(`      - ${f.id}: ${f.note} @ ${f.file}:${f.line}`);
		}
	}
	const d = p.deps;
	if (d !== undefined) {
		lines.push(`    deps: ${d.declared} declared, ${d.nestedScanned} nested scanned, ${d.unchecked} unchecked`);
		for (const ns of d.nestedScripts ?? []) {
			lines.push(`      - nested dep ${ns.name} has lifecycle scripts: ${ns.scripts.join(", ")}`);
		}
	}
	if (p.filesScanned !== undefined) {
		lines.push(`    coverage: ${p.filesScanned} source file(s), ${p.linesScanned ?? 0} line(s) scanned`);
	}
	if (p.runtimeSurface !== undefined) {
		const rs = p.runtimeSurface;
		const parts = [];
		if (rs.childProcess > 0) parts.push(`child_process x${rs.childProcess}`);
		if (rs.fetch > 0) parts.push(`fetch x${rs.fetch}`);
		if (rs.eval > 0) parts.push(`eval x${rs.eval}`);
		if (rs.sockets > 0) parts.push(`sockets x${rs.sockets}`);
		lines.push(`    runtime surface: ${parts.length > 0 ? parts.join(", ") : "none of exec/fetch/eval/socket detected"}`);
	}
	return lines.join("\n");
}

/** Render the full vet report. */
function renderReport(report) {
	const lines = [];
	lines.push(`# Plugin vet — ${report.scanned} third-party plugin(s) scanned`);
	lines.push(`safe=${report.summary.safe} low=${report.summary.low} medium=${report.summary.medium} high=${report.summary.high}`);
	for (const p of report.packages) lines.push("", renderPackage(p));
	for (const w of report.warnings) lines.push("", `> ${w}`);
	return lines.join("\n");
}

/** Install the optional subprocess tripwire (log-only, harness channel). */
function installMonitor(ctx) {
	const subprocess = ctx.get("subprocess");
	if (subprocess === undefined) return;
	const original = subprocess.spawn;
	if (typeof original !== "function") return;
	const FLAG_PATTERN = /(curl|wget|nc|ncat|telnet)\b.*(-X\s*POST|--data|\.onion|http:\/\/\d{1,3}\.|/proc\/\d+\/environ)/i;
	ctx.effect(() => {
		subprocess.spawn = (spec) => {
			const argv = Array.isArray(spec?.argv) ? spec.argv.join(" ") : String(spec?.command ?? "");
			if (FLAG_PATTERN.test(argv)) {
				const detail = argv.slice(0, 200);
				ctx.logger?.warn?.(`[plugin-vet] tripwire: suspicious spawn: ${detail}`);
			}
			return original(spec);
		};
		return () => {
			subprocess.spawn = original;
		};
	}, "plugin-vet: spawn tripwire");
}

/** Load the official-package hash baseline from disk (best-effort). */
function loadBaseline() {
	const file = join(resolveDshHome(), ".dsh-plugin-vetting", "baseline.json");
	try {
		const parsed = JSON.parse(readFileSync(file, "utf8"));
		return typeof parsed === "object" && parsed !== null ? parsed : {};
	} catch {
		return {};
	}
}

/** Persist the official-package hash baseline (best-effort). */
function saveBaseline(entries) {
	const file = join(resolveDshHome(), ".dsh-plugin-vetting", "baseline.json");
	try {
		mkdirSync(dirname(file), { recursive: true });
		writeFileSync(file, JSON.stringify(entries, null, 2) + "\n", "utf8");
	} catch {
		/* best-effort */
	}
}

/**
 * Register the tool and command.
 * @param ctx - host plugin context.
 * @param config - `{ roots?, monitor?, hashOfficial? }`.
 */
function apply(ctx, config) {
	const roots = Array.isArray(config?.roots) && config.roots.length > 0 ? config.roots : defaultRoots();
	if (config?.monitor === true) installMonitor(ctx);
	const baseline = config?.hashOfficial !== false ? { load: loadBaseline, save: saveBaseline } : undefined;

	const definition = {
		name: "plugin_vet",
		description: "Scan installed third-party DeepSeek Harness plugins for malicious behavior patterns (network exfiltration, credential access, obfuscation, persistence) and for accidentally-broad high-privilege path use (suggest-narrowing advisories). Static heuristic scan — never executes plugin code; runtime-dynamic code (downloaded then eval'd) is NOT in scope. Official @deepseek-ai/* packages are exempt but content-hash-verified against a baseline (supply-chain tampering detection). Returns per-package risk grade (SAFE/LOW/MEDIUM/HIGH) with file:line findings, scan coverage, and the runtime surface (child_process/fetch/eval/socket usage counts); packages containing eval/new Function are flagged [REVIEW] regardless of score.",
		parameters: {
			type: "object",
			properties: {}
		},
		output: {
			schema: {
				type: "object",
				additionalProperties: false,
				properties: {
					scanned: { type: "number" },
					packages: {
						type: "array",
						items: {
							type: "object",
							additionalProperties: false,
							properties: {
								name: { type: "string" },
								version: { type: "string" },
								risk: { type: "string" },
								score: { type: "number" },
								needsReview: { type: "boolean" },
								filesScanned: { type: "number" },
								linesScanned: { type: "number" },
								runtimeSurface: {
									type: "object",
									additionalProperties: false,
									properties: {
										childProcess: { type: "number" },
										fetch: { type: "number" },
										eval: { type: "number" },
										sockets: { type: "number" }
									}
								},
								findings: {
									type: "array",
									items: {
										type: "object",
										additionalProperties: false,
										properties: {
											id: { type: "string" },
											file: { type: "string" },
											line: { type: "number" },
											note: { type: "string" },
											weight: { type: "number" }
										}
									}
								},
								sloppyFindings: {
									type: "array",
									items: {
										type: "object",
										additionalProperties: false,
										properties: {
											id: { type: "string" },
											file: { type: "string" },
											line: { type: "number" },
											note: { type: "string" }
										}
									}
								},
								deps: {
									type: "object",
									additionalProperties: false,
									properties: {
										declared: { type: "number" },
										nestedScanned: { type: "number" },
										unchecked: { type: "number" },
										nestedScripts: {
											type: "array",
											items: {
												type: "object",
												additionalProperties: false,
												properties: {
													name: { type: "string" },
													scripts: { type: "array", items: { type: "string" } }
												}
											}
										}
									}
								}
							}
						}
					},
					summary: {
						type: "object",
						additionalProperties: false,
						properties: {
							safe: { type: "number" },
							low: { type: "number" },
							medium: { type: "number" },
							high: { type: "number" }
						}
					},
					warnings: { type: "array", items: { type: "string" } }
				}
			},
			render: (args, value) => [{ type: "text", text: renderReport(value) }]
		},
		async execute() {
			return runVet(roots, { allowlist: config?.allowlist ?? [], baseline });
		}
	};
	ctx.effect(() => ctx.tools.register(definition), "plugin-vet: tool");

	const commands = ctx.get("commands");
	if (commands !== undefined) {
		ctx.effect(() => commands.register({
			name: "plugin-vet",
			description: "Scan installed third-party plugins for malicious patterns and print the report",
			handler: async () => {
				const report = runVet(roots, { allowlist: config?.allowlist ?? [], baseline });
				return { kind: "success", text: renderReport(report) };
			}
		}), "plugin-vet: command");
	}
}

export { apply, inject, name };
