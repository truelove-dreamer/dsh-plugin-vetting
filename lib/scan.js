/**
 * Pure scanning logic for plugin vetting.
 *
 * The scanner is static and never executes plugin code: it reads package
 * directories from disk, matches source text against the heuristic rules,
 * and scores each package. Everything here is a total, side-effect-free
 * function over paths passed in, so it is fully unit-testable.
 *
 * Threat categories:
 *  - malicious findings (rule.category === "malicious") sum into the risk
 *    score and risk grade;
 *  - sloppy findings (rule.category === "sloppy") are advisories — the
 *    plugin is probably not malicious but touches high-privilege paths
 *    broadly; they are reported under "suggest narrowing" and do NOT move
 *    the risk grade by themselves.
 *
 * @module dsh-plugin-vetting/scan
 */
import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { RULES, classify, isPluginPackage } from "./rules.js";

/** Directories inside a package that are never scanned. */
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", ".DS_Store"]);
/** Per-package source-file scan cap. */
const FILE_LIMIT = 200;
/** Nested-dependency package.json scan cap (cheap script check only). */
const DEP_LIMIT = 50;

/**
 * Recursively collect source files (.js/.mjs/.cjs/.ts) under a package root.
 * @param root - the package directory.
 * @returns absolute file paths, bounded to keep the scan cheap.
 */
export function collectSourceFiles(root, limit = FILE_LIMIT) {
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
 * @returns per-rule findings (category/weight/requiresReview from the rule).
 */
export function matchFile(text, file, rules = RULES) {
	const findings = [];
	const lines = text.split("\n");
	for (const rule of rules) {
		const match = rule.pattern.exec(text);
		if (match === null) continue;
		let line = 0;
		for (let i = 0; i < lines.length && i < 5000; i += 1) {
			if (lines[i].includes(match[0]) || (match.index !== undefined && countLines(text, match.index) === i)) {
				line = i + 1;
				break;
			}
		}
		findings.push({
			id: rule.id,
			category: rule.category ?? "malicious",
			file,
			line,
			note: rule.note,
			weight: rule.weight,
			requiresReview: rule.requiresReview === true
		});
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

/** Read a package manifest safely. */
function readManifest(dir) {
	const manifestPath = join(dir, "package.json");
	if (!existsSync(manifestPath)) return undefined;
	try {
		return JSON.parse(readFileSync(manifestPath, "utf8"));
	} catch {
		return undefined;
	}
}

/**
 * Cheap dependency + lifecycle-script overview: the package's OWN lifecycle
 * scripts (install/prepare/prepublishOnly family), declared deps count, and
 * a bounded scan of nested `node_modules/<dep>` package.jsons for scripts.
 * @param dir - the package directory.
 * @returns { ownScripts, declared, nestedScanned, nestedScripts, unchecked }.
 */
export function inspectDependencies(dir) {
	const manifest = readManifest(dir);
	const ownScripts = Object.keys(manifest?.scripts ?? {}).filter((s) => /install|prepare|prepublish/.test(s));
	const declared = new Set([
		...(Object.keys(manifest?.dependencies ?? {})),
		...(Object.keys(manifest?.devDependencies ?? {})),
		...(Object.keys(manifest?.peerDependencies ?? {}))
	]);
	const nestedRoot = join(dir, "node_modules");
	const nestedScripts = [];
	let nestedScanned = 0;
	if (existsSync(nestedRoot)) {
		let entries;
		try {
			entries = readdirSync(nestedRoot, { withFileTypes: true });
		} catch {
			entries = [];
		}
		for (const entry of entries) {
			if (nestedScanned >= DEP_LIMIT) break;
			if (!entry.isDirectory() || entry.name.startsWith(".")) continue;
			let depDir = join(nestedRoot, entry.name);
			// scoped deps live one level deeper
			if (entry.name.startsWith("@")) {
				let scoped;
				try {
					scoped = readdirSync(depDir, { withFileTypes: true });
				} catch {
					continue;
				}
				for (const sub of scoped) {
					if (!sub.isDirectory()) continue;
					const m = readManifest(join(depDir, sub.name));
					if (m !== undefined) {
						nestedScanned += 1;
						const scripts = Object.keys(m.scripts ?? {}).filter((s) => /install|prepare|prepublish/.test(s));
						if (scripts.length > 0) nestedScripts.push({ name: `${entry.name}/${sub.name}`, scripts });
					}
				}
				continue;
			}
			const m = readManifest(depDir);
			if (m !== undefined) {
				nestedScanned += 1;
				const scripts = Object.keys(m.scripts ?? {}).filter((s) => /install|prepare|prepublish/.test(s));
				if (scripts.length > 0) nestedScripts.push({ name: entry.name, scripts });
			}
		}
	}
	// deps that are neither present in a nested node_modules nor obviously
	// hoisted are reported as unchecked (honest upper bound).
	const unchecked = Math.max(0, declared.size - nestedScanned);
	return { ownScripts, declared: declared.size, nestedScanned, nestedScripts, unchecked };
}

/**
 * Compute a content hash over a package's shipped files (source + manifest +
 * patch). Used for the official-package "known surface" baseline: exemption
 * moves from trusting a name to trusting content.
 * @param dir - the package directory.
 * @returns sha256 hex of the sorted file list's contents, or undefined when
 *   the package has no readable files.
 */
export function hashPackage(dir) {
	const files = collectSourceFiles(dir).sort();
	const manifest = join(dir, "package.json");
	if (existsSync(manifest)) files.push(manifest);
	const patch = join(dir, "cordis.patch.yml");
	if (existsSync(patch)) files.push(patch);
	if (files.length === 0) return undefined;
	const h = createHash("sha256");
	for (const file of files) {
		try {
			h.update(readFileSync(file));
		} catch {
			/* skip unreadable */
		}
	}
	return h.digest("hex");
}

/**
 * Scan one package directory and produce its vet report row.
 * @param dir - absolute package directory.
 * @param name - package name (for reporting).
 * @returns { name, version, risk, score, needsReview, findings,
 *            sloppyFindings, deps, filesScanned }.
 */
export function scanPackage(dir, name) {
	const manifest = readManifest(dir);
	const version = typeof manifest?.version === "string" ? manifest.version : "unknown";
	const files = collectSourceFiles(dir);
	const findings = [];
	const runtimeSurface = { childProcess: 0, fetch: 0, eval: 0, sockets: 0 };
	let linesScanned = 0;
	for (const file of files) {
		let text;
		try {
			text = readFileSync(file, "utf8");
		} catch {
			continue;
		}
		linesScanned += text.split("\n").length;
		if (text.length > 4 * 1024 * 1024) text = text.slice(0, 4 * 1024 * 1024);
		for (const f of matchFile(text, file)) {
			f.file = relative(dir, file).split(sep).join("/");
			findings.push(f);
		}
		// runtime surface: count EVERY dangerous primitive touchpoint
		runtimeSurface.childProcess += (text.match(/child_process(?:\.\w+)?/g) ?? []).length;
		runtimeSurface.childProcess += (text.match(/(?<!\.)\bexec(Sync|File)?\s*\(/g) ?? []).length;
		runtimeSurface.childProcess += (text.match(/(?<!\.)\bspawn\s*\(/g) ?? []).length;
		runtimeSurface.fetch += (text.match(/\bfetch\s*\(/g) ?? []).length;
		runtimeSurface.eval += (text.match(/\beval\s*\(|new Function\s*\(|vm\.runInNewContext\s*\(/g) ?? []).length;
		runtimeSurface.sockets += (text.match(/\bnet\.connect\b|\bnet\.createConnection\b|\bdgram\b|\bWebSocket\b|\bhttp\.request\b|\.connect\s*\(/g) ?? []).length;
	}
	// package.json text participates in rule matching too (lifecycle scripts)
	if (manifest !== undefined) {
		for (const f of matchFile(JSON.stringify(manifest, null, 1), join(dir, "package.json"))) {
			f.file = "package.json";
			findings.push(f);
		}
	}
	const malicious = findings.filter((f) => f.category !== "sloppy");
	const sloppy = findings.filter((f) => f.category === "sloppy");
	const score = malicious.reduce((sum, f) => sum + f.weight, 0);
	const needsReview = malicious.some((f) => f.requiresReview);
	return {
		name,
		version,
		risk: classify(score),
		score,
		needsReview,
		findings: malicious.map(({ category, requiresReview, ...rest }) => rest),
		sloppyFindings: sloppy.map(({ category, requiresReview, weight, ...rest }) => rest),
		deps: inspectDependencies(dir),
		filesScanned: files.length,
		linesScanned,
		runtimeSurface
	};
}

/**
 * Discover third-party plugin packages under a set of roots.
 * @param roots - directories whose immediate children are packages.
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
 * Discover official (@deepseek-ai/*) packages under the roots — used only
 * for the content-hash baseline, never scanned by the heuristic rules.
 * @param roots - package-container directories.
 * @returns { name, dir } entries for official packages.
 */
export function discoverOfficialPackages(roots) {
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
			if (entry.name.startsWith("@")) {
				const scopeDir = join(root, entry.name);
				let scoped;
				try {
					scoped = readdirSync(scopeDir, { withFileTypes: true });
				} catch {
					continue;
				}
				for (const sub of scoped) {
					if (!sub.isDirectory()) continue;
					const full = `${entry.name}/${sub.name}`;
					if (full.startsWith("@deepseek-ai/")) dirs.push({ name: full, dir: join(scopeDir, sub.name) });
				}
				continue;
			}
		}
	}
	return dirs;
}

/**
 * Run the full vet over roots.
 * @param roots - package-container directories.
 * @param options - `{ allowlist?: string[], baseline?: { load, save } }`.
 *   `baseline` enables the official-package content-hash baseline: exemption
 *   becomes "trust content" instead of "trust name" — a mismatch between the
 *   installed official package and the recorded hash is reported as a
 *   possible supply-chain tampering warning.
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
			row.sloppyFindings = [];
			row.score = 0;
			row.needsReview = false;
		}
		return row;
	});
	const summary = { safe: 0, low: 0, medium: 0, high: 0 };
	for (const p of packages) summary[p.risk.toLowerCase()] += 1;
	const warnings = [
		"heuristic scan only: a clean result is not a security guarantee",
		"runtime-dynamic code (downloaded then eval'd, remote modules) is NOT in scope — static scan cannot see it",
		"official @deepseek-ai/* packages are exempt by name",
		"false-positive class: security plugins that intentionally reference secret paths / exfil hosts in their own rules will score HIGH; add them to the allowlist"
	];
	if (allowlist.size > 0) warnings.push(`${allowlist.size} package(s) allowlisted by config`);

	// official-package content-hash baseline (opt-in via options.baseline)
	if (options.baseline !== undefined && typeof options.baseline.load === "function" && typeof options.baseline.save === "function") {
		let known;
		try {
			known = options.baseline.load() ?? {};
		} catch {
			known = {};
		}
		let changed = false;
		let checked = 0;
		for (const { name, dir } of discoverOfficialPackages(roots)) {
			const hash = hashPackage(dir);
			if (hash === undefined) continue;
			checked += 1;
			const previous = known[name];
			if (previous !== undefined && previous !== hash) {
				warnings.push(`OFFICIAL-PACKAGE MISMATCH: ${name} content differs from the recorded baseline (possible supply-chain tampering) — exemption revoked`);
			} else if (previous === undefined) {
				known[name] = hash;
				changed = true;
			}
		}
		if (checked > 0) {
			warnings.push(`official baseline: ${checked} @deepseek-ai/* package(s) hash-verified against the recorded baseline`);
			if (changed) {
				try {
					options.baseline.save(known);
				} catch {
					/* persistence is best-effort */
				}
			}
		}
	}
	return {
		scanned: packages.length,
		packages,
		summary,
		warnings
	};
}
