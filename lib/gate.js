/**
 * Pure gate-decision logic for the plugin-tool gate.
 *
 * The gate answers one question per tool call: may a tool with this name
 * execute under the configured mode? The trusted set is built once at gate
 * install time from the harness's built-in tool schemas, plus this plugin's
 * own tool, plus any explicit `allowlistTools` entries. Tools registered
 * AFTER the gate installs (i.e. tools provided by plugins) are unvetted and
 * denied under `deny-unvetted` mode unless allowlisted.
 *
 * Honest boundaries (documented in the README):
 *  - this gates the TOOL-CALL surface (calls the model makes to plugin
 *    tools), NOT plugin-internal code (child_process/fetch/eval inside the
 *    plugin body at load time or in event handlers);
 *  - attribution is by tool NAME: a plugin that registers a tool with a
 *    built-in name (scoped shadowing) would pass the name check — a
 *    heuristic gate, not a security boundary;
 *  - a disabled guard is worse than none: if false positives make a user
 *    turn the gate off entirely, unvetted tools run unrestricted. Hence the
 *    default mode is "off".
 *
 * @module dsh-plugin-vetting/gate
 */

/**
 * Decide whether a tool call may proceed.
 * @param name - the tool name being executed.
 * @param trusted - set of trusted tool names (built-ins + own + allowlist).
 * @param mode - "off" (default) or "deny-unvetted".
 * @returns a denial reason string, or undefined to allow.
 */
export function gateDecision(name, trusted, mode = "off") {
	if (mode !== "deny-unvetted") return undefined;
	if (trusted.has(name)) return undefined;
	return `[plugin-vet gate] tool "${name}" is not a built-in harness tool and is not allowlisted — refusing to execute an unvetted plugin tool (gate mode: deny-unvetted; add it to allowlistTools to permit)`;
}
