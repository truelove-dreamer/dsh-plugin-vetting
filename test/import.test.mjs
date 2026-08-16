import { test } from "node:test";
import assert from "node:assert/strict";

// Parse-time smoke test: importing the plugin ENTRY must not throw.
// A SyntaxError inside any regex literal or module-level construct of
// lib/index.js previously shipped undetected (see issues #1/#3) because the
// unit tests only imported lib/scan.js, lib/rules.js, lib/gate.js.

test("lib/index.js imports cleanly (no parse-time errors)", async () => {
	const mod = await import("../lib/index.js");
	assert.equal(typeof mod.name, "string");
	assert.equal(typeof mod.apply, "function");
	assert.ok(Array.isArray(mod.inject));
});

test("all lib modules import cleanly", async () => {
	await import("../lib/scan.js");
	await import("../lib/rules.js");
	await import("../lib/gate.js");
	assert.ok(true);
});

// Regression: the output schema must declare EVERY field runVet can set on a
// package row, or the harness rejects the tool result under
// additionalProperties:false (see issue #4 / PR #5 — allowlisted was missing
// and broke plugin_vet for allowlist users).
test("output schema declares allowlisted (PR #5 regression)", async () => {
	const mod = await import("../lib/index.js");
	let definition;
	const fakeTools = {
		register(d) { definition = d; return () => {}; },
		schemas() { return []; },
		guard() { return () => {}; }
	};
	mod.apply({ tools: fakeTools, get() { return undefined; }, effect(fn) { fn(); } }, {});
	assert.ok(definition !== undefined, "tool definition should be registered");
	const items = definition.output.schema.properties.packages.items.properties;
	assert.ok("allowlisted" in items, "packages[].allowlisted must be declared in output schema");
	assert.equal(items.allowlisted.type, "boolean");
});

// Regression: link:/junction-installed plugins must be discovered (PR #5).
// A junction looks like isSymbolicLink()===true, isDirectory()===false at the
// top level of node_modules; discovery must still follow it.
test("discoverPluginPackages follows junction/symlink entries", async () => {
	const { discoverPluginPackages } = await import("../lib/scan.js");
	const { mkdtempSync, mkdirSync, symlinkSync, writeFileSync, rmSync } = await import("node:fs");
	const { tmpdir } = await import("node:os");
	const { join } = await import("node:path");
	const root = mkdtempSync(join(tmpdir(), "vet-link-"));
	const nm = join(root, "node_modules");
	const realPkg = join(root, "real-plugin");
	mkdirSync(nm, { recursive: true });
	mkdirSync(realPkg, { recursive: true });
	writeFileSync(join(realPkg, "package.json"), JSON.stringify({ name: "dsh-plugin-linked", version: "1.0.0" }));
	try {
		symlinkSync(realPkg, join(nm, "dsh-plugin-linked"), process.platform === "win32" ? "junction" : "dir");
	} catch {
		rmSync(root, { recursive: true, force: true });
		return; // environment without symlink permission — skip
	}
	const found = discoverPluginPackages([nm]);
	assert.equal(found.length, 1, "junction-installed plugin must be discovered");
	assert.equal(found[0].name, "dsh-plugin-linked");
	rmSync(root, { recursive: true, force: true });
});
