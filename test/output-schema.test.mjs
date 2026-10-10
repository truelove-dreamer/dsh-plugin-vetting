import { test } from "node:test";
import assert from "node:assert/strict";

// Regression: the output schema must declare EVERY field the renderer emits on a
// finding row, or the harness rejects the whole tool result under
// additionalProperties:false. runVet sets noteZh on findings and sloppyFindings
// (see renderPackage in lib/index.js), but the schema declared only `note` — so
// plugin_vet returned no result at all on dsh 0.2.x. Same failure mode as the
// missing `allowlisted` declaration fixed in issue #4 / PR #5.

test("output schema declares noteZh on finding rows", async () => {
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
	for (const scope of ["findings", "sloppyFindings"]) {
		const node = items[scope];
		assert.ok(node !== undefined, `${scope} must exist in the output schema`);
		assert.equal(node.items.additionalProperties, false, `${scope} keeps additionalProperties:false`);
		assert.ok(
			"noteZh" in node.items.properties,
			`${scope}[].noteZh must be declared in the output schema — the renderer emits it, and the harness rejects an undeclared field`
		);
		assert.equal(node.items.properties.noteZh.type, "string");
	}
});

// Guard against the whole class of bug: every key the renderer interpolates on a
// finding row must exist in the schema. Keep this list in sync with the
// template literal in renderPackage.
test("every field renderPackage interpolates is declared in the schema", async () => {
	const mod = await import("../lib/index.js");
	let definition;
	const fakeTools = {
		register(d) { definition = d; return () => {}; },
		schemas() { return []; },
		guard() { return () => {}; }
	};
	mod.apply({ tools: fakeTools, get() { return undefined; }, effect(fn) { fn(); } }, {});

	const { readFileSync } = await import("node:fs");
	const src = readFileSync(new URL("../lib/index.js", import.meta.url), "utf8");

	// finding rows are rendered as: `${f.id}: ${f.note} ${f.noteZh ...} @ ${f.file}:${f.line}`
	const rendered = [...src.matchAll(/\$\{f\.(\w+)\}/g)].map((m) => m[1]);
	assert.ok(rendered.length > 0, "expected to find finding-row interpolations in the source");
	const unique = [...new Set(rendered)];

	const items = definition.output.schema.properties.packages.items.properties;
	for (const scope of ["findings", "sloppyFindings"]) {
		const declared = Object.keys(items[scope].items.properties);
		const missing = unique.filter((f) => !declared.includes(f));
		assert.deepEqual(missing, [], `${scope}[] is missing declarations for renderer fields: ${missing.join(", ")}`);
	}
});
