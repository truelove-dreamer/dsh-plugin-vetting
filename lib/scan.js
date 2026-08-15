/**
 * Pure scanning logic for plugin vetting.
 *
 * The scanner is static and never executes plugin code: it reads package
 * directories from disk, matches source text against the heuristic rules,
 * and scores each package. Everything here is a total, side-effect-free
 * function over paths passed in, so it is fully unit-testable.
 *
 * @module dsh-plugin-vet/scan
 */
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { RULES, classify, isPluginPackage } from "./rules.js";

/** Directories inside a package that are never scanned. */
const SKIP_DIRS = new Set(["node_modules", ".git", "dist"]);

/**
 * Recursively collect source files (.js/.mjs/.cjs/.ts) under a package root.
 * @param root - the package directory.
 * @returns absolute file paths, bounded to keep the scan cheap.
 */
export function collectSourceFiles(root, limit = 200) {
	const out = [];
	const walk = (dir) => {
		if (out.length >= limit) return;
		let entries;
		try {
			entries = readdirSync(dir, { withFileTypes: true });
		} catch {
			return;
		}
		for (const entry of entries) {
			if (out.length >= limit) return;
			if (entry.isDirectory()) {
				if (SKIP_DIRS.has(entry.name)) continue;
				walk(join(dir, entry.name));
				continue;
			}
			if (/\.(js|mjs|cjs|ts)$/.test(entry.name)) out.push(join(dir, entry.name));
		}
	};
	walk(root);
	return out;
}

/**
 * Match one file's text against the rules.
 * @param text - full source text.
 * @param file - absolute path (for reporting).
 * @param rules - rule list (defaults to RULES).
 * @returns per-rule findings with the first matching line number.
 */
export function matchFile(text, file, rules = RULES) {
	const findings = [];
	const lines = text.split("\n");
	for (const rule of rules) {
		const match = rule.pattern.exec(text);
		if (match === null) continue;
		let line = 0;
		// find the first line containing the match (bounded scan)
		for (let i = 0; i < lines.length && i < 5000; i += 1) {
			if (lines[i].includes(match[0]) || (match.index !== undefined && countLines(text, match.index) === i)) {
				line = i + 1;
				break;
			}
		}
		findings.push({ id: rule.id, file, line, note: rule.note, weight: rule.weight });
	}
	return findings;
}

/** Count how many newlines precede a character index (helper). */
function countLines(text, index) {
	let n = 0;
	for (let i = 0; i < index && i < text.length; i += 1) {
		if (text.charCodeAt(i) === 10) n += 1;
	}
	return n;
}

/**
 * Scan one package directory and produce its vet report row.
 * @param dir - absolute package directory.
 * @param name - package name (for reporting).
 * @returns { name, version, risk, score, findings }.
 */
export function scanPackage(dir, name) {
	let version = "unknown";
	const manifestPath = join(dir, "package.json");
	if (existsSync(manifestPath)) {
		try {
			const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
			if (typeof manifest.version === "string") version = manifest.version;
		} catch {
			/* keep "unknown" */
		}
	}
	const files = collectSourceFiles(dir);
	const findings = [];
	for (const file of files) {
		let text;
		try {
			text = readFileSync(file, "utf8");
		} catch {
			continue;
		}
		if (text.length > 4 * 1024 * 1024) text = text.slice(0, 4 * 1024 * 1024); // cap per-file scan
		for (const f of matchFile(text, file)) {
			f.file = relative(dir, file).split(sep).join("/");
			findings.push(f);
		}
	}
	const score = findings.reduce((sum, f) => sum + f.weight, 0);
	return { name, version, risk: classify(score), score, findings };
}

/**
 * Discover third-party plugin packages under a set of roots.
 * @param roots - directories whose immediate children are packages
 *   (e.g. a profile's node_modules).
 * @returns absolute directories of plugin-looking, non-official packages.
 */
export function discoverPluginPackages(roots) {
	const dirs = [];
	for (const root of roots) {
		if (!existsSync(root)) continue;
		let entries;
		try {
			entries = readdirSync(root, { withFileTypes: true });
		} catch {
			continue;
		}
		for (const entry of entries) {
			if (!entry.isDirectory()) continue;
			const name = entry.name;
			// scoped packages live one level deeper
			if (name.startsWith("@")) {
				const scopeDir = join(root, name);
				let scoped;
				try {
					scoped = readdirSync(scopeDir, { withFileTypes: true });
				} catch {
					continue;
				}
				for (const sub of scoped) {
					if (!sub.isDirectory()) continue;
					const full = `${name}/${sub.name}`;
					if (isPluginPackage(full) && !sub.name.startsWith(".")) dirs.push({ name: full, dir: join(scopeDir, sub.name) });
				}
				continue;
			}
			if (isPluginPackage(name)) dirs.push({ name, dir: join(root, name) });
		}
	}
	return dirs;
}

/**
 * Run the full vet over roots.
 * @param roots - package-container directories.
 * @param options - `{ allowlist?: string[] }` — package names to mark SAFE
 *   (e.g. your own security plugins that intentionally reference secret
 *   patterns in their rules).
 * @returns { scanned, packages, summary, warnings }.
 */
export function runVet(roots, options = {}) {
	const allowlist = new Set(options.allowlist ?? []);
	const discovered = discoverPluginPackages(roots);
	const packages = discovered.map(({ name, dir }) => {
		const row = scanPackage(dir, name);
		if (allowlist.has(name)) {
			row.risk = "SAFE";
			row.allowlisted = true;
			row.findings = [];
			row.score = 0;
		}
		return row;
	});
	const summary = { safe: 0, low: 0, medium: 0, high: 0 };
	for (const p of packages) summary[p.risk.toLowerCase()] += 1;
	const warnings = [
		"heuristic scan only: a clean result is not a security guarantee",
		"official @deepseek-ai/* packages are exempt by name",
		"false-positive class: security plugins that intentionally reference secret paths / exfil hosts in their own rules will score HIGH; add them to the allowlist"
	];
	if (allowlist.size > 0) warnings.push(`${allowlist.size} package(s) allowlisted by config`);
	return {
		scanned: packages.length,
		packages,
		summary,
		warnings
	};
}
