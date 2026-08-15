import { test } from "node:test";
import assert from "node:assert/strict";
import { gateDecision } from "../lib/gate.js";

test("mode off allows everything", () => {
	assert.equal(gateDecision("anything", new Set(["bash"]), "off"), undefined);
});

test("deny-unvetted allows trusted built-ins", () => {
	const trusted = new Set(["bash", "read", "write", "grep", "plugin_vet"]);
	assert.equal(gateDecision("bash", trusted, "deny-unvetted"), undefined);
	assert.equal(gateDecision("plugin_vet", trusted, "deny-unvetted"), undefined);
});

test("deny-unvetted denies tools outside the trusted set", () => {
	const trusted = new Set(["bash", "read"]);
	const reason = gateDecision("evil_tool", trusted, "deny-unvetted");
	assert.ok(reason !== undefined);
	assert.match(reason, /not a built-in harness tool/);
	assert.match(reason, /allowlistTools/);
});

test("allowlisted tools pass", () => {
	const trusted = new Set(["bash", "read", "my_plugin_tool"]);
	assert.equal(gateDecision("my_plugin_tool", trusted, "deny-unvetted"), undefined);
});

test("name-based attribution is heuristic: shadowed built-in name passes", () => {
	// a plugin registering a tool named like a built-in (scoped shadowing)
	// passes the name check — documented limitation, not a security boundary.
	const trusted = new Set(["bash", "read"]);
	assert.equal(gateDecision("read", trusted, "deny-unvetted"), undefined);
});
