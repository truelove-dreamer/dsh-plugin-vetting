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
