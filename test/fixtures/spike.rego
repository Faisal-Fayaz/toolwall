package firewall

# toolwall decision policy (spike version).
#
# Precedence is deny > ask > allow: every matching rule is collected and the
# strongest effect wins. First-match semantics are NOT used — a `.env` read
# under the workspace matches both `no-secret-reads` (deny) and
# `workspace-reads` (allow), and must resolve to deny.
#
# Wasm-runtime constraints (see docs/M0.md):
#   - no `%q` in sprintf (runtime backs it with sprintf-js, which lacks the verb)

default decision := {
	"effect": "deny",
	"rule": "default",
	"reason": "no rule matched",
}

# all rules that match this call
matched contains r if {
	some r in rules
	matches(input, r)
}

# the set of effects proposed by matched rules
effects := {r.effect | some r in matched}

default winning_effect := "allow"

winning_effect := "deny" if "deny" in effects

winning_effect := "ask" if {
	not "deny" in effects
	"ask" in effects
}

decision := {
	"effect": winning_effect,
	"rule": winner.name,
	"reason": reason_for(winner, input),
} if {
	some r in matched
	r.effect == winning_effect
	winner := r
}

matches(inp, r) if {
	some t in r.tools
	tool_matches(inp.tool.name, t)
}

# glob match supporting * and **
tool_matches(name, pattern) if {
	endswith(pattern, "**")
	startswith(name, substring(pattern, 0, count(pattern) - 2))
}

tool_matches(name, pattern) if {
	not endswith(pattern, "**")
	name == pattern
}

# --- argument-level rules (the wedge) ---

# deny by ARGUMENT, not by tool name
rules contains {
	"name": "no-secret-reads",
	"effect": "deny",
	"tools": ["Read", "mcp__fs__read_file", "mcp__fs__write_file"],
} if {
	path_contains_secret(input.arguments.path)
}

# NOTE: in Rego v1, `"lit" in some_object` tests VALUES, not keys. For key
# presence use object.get(obj, "lit", null) != null.
rules contains {
	"name": "no-network",
	"effect": "deny",
	"tools": ["Bash", "mcp__http__fetch"],
} if {
	object.get(input.arguments, "network", null) != null
}

# allow reads inside the workspace (lowest precedence — loses to any deny)
rules contains {
	"name": "workspace-reads",
	"effect": "allow",
	"tools": ["Read", "Glob", "Grep", "mcp__fs__read_file", "mcp__fs__list_directory"],
} if {
	path_is_within(input.agent.cwd, input.arguments.path)
}

reason_for(r, inp) := sprintf("rule '%s' matched for tool '%s'", [r.name, inp.tool.name])