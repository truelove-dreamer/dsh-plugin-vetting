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
 * /proc/<pid>/environ, ...). Log-only; it never blocks.
 *
 * Mount it in a profile patch or agent preset:
 *   - id: plugin-vet
 *     name: dsh-plugin-vet
 *     config:
 *       roots: [ ... ]        # package-container dirs; defaults below
 *       monitor: false        # enable the subprocess tripwire
 *
 * @module dsh-plugin-vet
 */
import { homedir } from "node:os";
import { existsSync, readdirSync } from "node:fs";
import { join } from "node:path";
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
	const lines = [`[${p.risk}] ${p.name}@${p.version} (score ${p.score})`];
	for (const f of p.findings.slice(0, 10)) {
		lines.push(`    - ${f.id}: ${f.note} @ ${f.file}:${f.line}`);
	}
	if (p.findings.length > 10) lines.push(`    ... and ${p.findings.length - 10} more`);
	if (p.findings.length === 0) lines.push("    (no heuristic hits)");
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

/** Install the optional subprocess tripwire (log-only). */
function installMonitor(ctx, roots) {
	const subprocess = ctx.get("subprocess");
	if (subprocess === undefined) return;
	const original = subprocess.spawn;
	if (typeof original !== "function") return;
	const FLAG_PATTERN = /(curl|wget|nc|ncat|telnet)\b.*(-X\s*POST|--data|\.onion|http:\/\/\d{1,3}\.|/proc\/\d+\/environ)/i;
	ctx.effect(() => {
		subprocess.spawn = (spec) => {
			const argv = Array.isArray(spec?.argv) ? spec.argv.join(" ") : String(spec?.command ?? "");
			if (FLAG_PATTERN.test(argv)) {
				ctx.logger?.warn?.(`[plugin-vet] tripwire: suspicious spawn: ${argv.slice(0, 200)}`);
			}
			return original(spec);
		};
		return () => {
			subprocess.spawn = original;
		};
	}, "plugin-vet: spawn tripwire");
}

/**
 * Register the tool and command.
 * @param ctx - host plugin context.
 * @param config - `{ roots?, monitor? }`.
 */
function apply(ctx, config) {
	const roots = Array.isArray(config?.roots) && config.roots.length > 0 ? config.roots : defaultRoots();
	if (config?.monitor === true) installMonitor(ctx, roots);

	const definition = {
		name: "plugin_vet",
		description: "Scan installed third-party DeepSeek Harness plugins for malicious behavior patterns (network exfiltration, credential access, obfuscation, persistence). Static heuristic scan — never executes plugin code. Official @deepseek-ai/* packages are exempt. Returns a per-package risk grade (SAFE/LOW/MEDIUM/HIGH) with file:line findings.",
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
			return runVet(roots, { allowlist: config?.allowlist ?? [] });
		}
	};
	ctx.effect(() => ctx.tools.register(definition), "plugin-vet: tool");

	const commands = ctx.get("commands");
	if (commands !== undefined) {
		ctx.effect(() => commands.register({
			name: "plugin-vet",
			description: "Scan installed third-party plugins for malicious patterns and print the report",
			handler: async () => {
				const report = runVet(roots, { allowlist: config?.allowlist ?? [] });
				return { kind: "success", text: renderReport(report) };
			}
		}), "plugin-vet: command");
	}
}

export { apply, inject, name };
