package firewall

# toolwall default policy.
#
# Rules are DATA, not Rego expressions: a rule is an object with `effect`,
# `tools`, and any number of declarative constraints. That means users can add
# rules from a plain JSON file without writing Rego or installing the OPA CLI.
#
# Precedence is deny > ask > allow. Every matching rule is collected and the
# strongest effect wins — first-match is NOT used. Reading .env inside the
# workspace matches both `no-secret-reads` (deny) and `workspace-reads` (allow)
# and must resolve to deny.
#
# Wasm-runtime constraints (see docs/M0.md):
#   - no `%q` in sprintf (runtime backs it with sprintf-js, which lacks the verb)
#   - `"lit" in obj` tests VALUES, not keys; use object.get(obj, "lit", null)

default decision := {
	"effect": "deny",
	"rule": "default-deny",
	"reason": "no rule matched; toolwall denies by default",
}

# ---------------------------------------------------------------- rule sources

default user_rules := []

# User rules live under a SEPARATE top-level package (data.toolwall), because
# data.firewall is this policy's own package — referencing data.firewall.user_rules
# from here is a self-reference and OPA rejects it as recursive.
user_rules := as_list(object.get(data.toolwall, "user_rules", [])) if {
	object.get(data.toolwall, "user_rules", null) != null
}

# `rules` is a partial SET, not an array — a helper that type-checks with
# is_array() silently turns it into [], which looks like "no rules matched"
# and fails closed on every call. Convert with a comprehension instead.
default_rules := [r | some r in rules]

user_rule_list := [r | some r in user_rules]

# Layering is by rule NAME: a user rule with the same name as a built-in
# REPLACES it, so a project can retune one specific rule without restating
# the rest. Without this, both copies would be evaluated together.
overridden(r) if {
	some u in user_rules
	u.name == r.name
}

effective_rules := [r | some r in default_rules; not overridden(r)]

all_rules := array.concat(effective_rules, user_rule_list)

# Normalize a scalar-or-array field into a list, so a rule may write
# "tools": "Read" instead of "tools": ["Read"].
as_list(x) := x if is_array(x)

as_list(x) := [x] if is_string(x)

# ------------------------------------------------------------- rule matching

matched contains r if {
	some r in all_rules
	matches(input, r)
}

matches(inp, r) if {
	is_object(r)
	object.get(r, "effect", "") in ["allow", "deny", "ask"]
	some t in as_list(object.get(r, "tools", []))
	tool_matches(inp.tool.name, t)
	constraints_ok(inp, r)
}

# glob matching for tool names: exact, prefix* or prefix**
tool_matches(name, pattern) if {
	endswith(pattern, "**")
	startswith(name, substring(pattern, 0, count(pattern) - 2))
}

tool_matches(name, pattern) if {
	endswith(pattern, "*")
	not endswith(pattern, "**")
	startswith(name, substring(pattern, 0, count(pattern) - 1))
}

tool_matches(name, pattern) if {
	not endswith(pattern, "*")
	name == pattern
}

# ---------------------------------------------------------------- constraints

CONSTRAINTS := {
	"path_secret",
	"path_within_cwd",
	"path_outside_cwd",
	"destructive",
	"read_only",
	"arg_key_present",
	"arg_path_prefix",
	"arg_path_suffix",
	"command_contains",
	"command_starts_with",
	"uses_secret",
	"secret_names",
}

# Matches when the arguments carry a `{{secret:…}}` reference. Gating USE of a
# brokered credential matters as much as gating READ of a credential file: a
# reference is a capability, and one that can be pasted into an arbitrary API
# call is worth spending deliberately.
constraint_holds(inp, c, r) if {
	c == "uses_secret"
	object.get(r, "uses_secret", false) == true
	contains_secret_ref(input.arguments)
}

constraint_holds(inp, c, r) if {
	c == "secret_names"
	some name in as_list(object.get(r, "secret_names", []))
	contains_secret_ref_named(input.arguments, name)
}

# Advisory shell checks. Substring matching on the raw command line only —
# it is trivially evaded via eval, $(...), variables and aliases. It exists to
# catch accidental damage, NOT to be a security boundary. The real boundary is
# OS-level isolation (sandbox / egress allowlist), never this.
constraint_holds(inp, c, r) if {
	c == "command_contains"
	some needle in as_list(object.get(r, "command_contains", []))
	contains(lower(object.get(inp.arguments, "command", "")), lower(needle))
}

constraint_holds(inp, c, r) if {
	c == "command_starts_with"
	some prefix in as_list(object.get(r, "command_starts_with", []))
	startswith(lower(object.get(inp.arguments, "command", "")), lower(prefix))
}

declared(r) := {c | some c in CONSTRAINTS; object.get(r, c, null) != null}

# A rule matches only when EVERY constraint it declares holds.
constraints_ok(inp, r) if {
	every c in declared(r) {
		constraint_holds(inp, c, r)
	}
}

constraint_holds(inp, c, r) if {
	c == "path_secret"
	object.get(r, "path_secret", false) == true
	path_contains_secret(object.get(inp.arguments, "path", ""))
}

constraint_holds(inp, c, r) if {
	c == "path_within_cwd"
	object.get(r, "path_within_cwd", false) == true
	path_is_within(object.get(inp.agent, "cwd", ""), object.get(inp.arguments, "path", ""))
}

constraint_holds(inp, c, r) if {
	c == "path_outside_cwd"
	object.get(r, "path_outside_cwd", false) == true
	not path_is_within(object.get(inp.agent, "cwd", ""), object.get(inp.arguments, "path", ""))
}

# gates on the MCP tool annotations, so readOnlyHint/destructiveHint finally
# become load-bearing rather than advisory
constraint_holds(inp, c, r) if {
	c == "destructive"
	object.get(r, "destructive", false) == true
	object.get(object.get(inp.tool, "annotations", {}), "destructiveHint", false) == true
}

constraint_holds(inp, c, r) if {
	c == "read_only"
	object.get(r, "read_only", false) == true
	object.get(object.get(inp.tool, "annotations", {}), "readOnlyHint", false) == true
}

# ANY of the listed keys being present triggers the rule. (ANY, not ALL —
# an `every` here means a rule listing three trigger keys only fires when all
# three are present, which silently disables it.)
constraint_holds(inp, c, r) if {
	c == "arg_key_present"
	some k in as_list(object.get(r, "arg_key_present", []))
	object.get(inp.arguments, k, null) != null
}

constraint_holds(inp, c, r) if {
	c == "arg_path_prefix"
	startswith(object.get(inp.arguments, "path", ""), object.get(r, "arg_path_prefix", ""))
}

constraint_holds(inp, c, r) if {
	c == "arg_path_suffix"
	endswith(object.get(inp.arguments, "path", ""), object.get(r, "arg_path_suffix", ""))
}

# ----------------------------------------------------------------- precedence

effects := {r.effect | some r in matched}

default winning_effect := "allow"

winning_effect := "deny" if "deny" in effects

winning_effect := "ask" if {
	not "deny" in effects
	"ask" in effects
}

# Several rules may share the winning effect (e.g. two allow rules). Bind
# exactly ONE of them deterministically — binding an iteration variable would
# make `decision` have conflicting definitions and the engine would fail closed
# on every call.
decision := {
	"effect": winning_effect,
	"rule": winner.name,
	"reason": reason_for(winner, input),
} if {
	winners := sort([r | some r in matched; r.effect == winning_effect])
	count(winners) > 0
	winner := winners[0]
}

# ----------------------------------------------------------- default rule set

rules contains {
	"name": "no-secret-reads",
	"effect": "deny",
	"tools": ["*"],
	"path_secret": true,
	"reason": "refusing to read or write a credential path",
} if {
	path_contains_secret(object.get(input.arguments, "path", ""))
}

rules contains {
	"name": "no-egress",
	"effect": "deny",
	"tools": ["*"],
	"arg_key_present": ["network", "url", "host"],
	"reason": "refusing outbound network access",
} if {
	some k in ["network", "url", "host"]
	object.get(input.arguments, k, null) != null
}

rules contains {
	"name": "no-system-paths",
	"effect": "deny",
	"tools": ["*"],
	"arg_path_prefix": "/etc",
	"reason": "refusing access to /etc",
}

rules contains {
	"name": "workspace-scoped",
	"effect": "allow",
	"tools": ["*"],
	"path_within_cwd": true,
	"reason": "path is inside the agent working directory",
}

# Advisory only — see the command_contains constraint note above.
rules contains {
	"name": "no-force-push",
	"effect": "deny",
	"tools": ["Bash"],
	"command_contains": ["push --force", "push -f"],
	"reason": "force-pushing can destroy history; not permitted",
}

# Shell commands carry a `command`, not a `path`, so no path rule matches them
# and they would otherwise fall through to default-deny — meaning even
# `npm run build` is blocked. `ask` routes them to a human instead, which is
# what toolwall can honestly claim: it defers shell decisions, it does not
# authorize them. Explicit denies above still win over this.
rules contains {
	"name": "shell-needs-human",
	"effect": "ask",
	"tools": ["Bash", "BashOutput"],
	"reason": "shell commands are reviewed by a human, not auto-approved",
}

# Brokered credentials are a capability. By default only tools that obviously
# need them may spend one; anything else has to be opted in explicitly.
rules contains {
	"name": "secret-use-restricted",
	"effect": "deny",
	"tools": ["*"],
	"uses_secret": true,
	"reason": "this tool may not use a brokered credential; allow it explicitly in policy",
}

# Exactly one body may apply, or `decision` gets conflicting definitions and
# the engine fails closed. A rule with a custom reason must NOT also fall
# through to the generated one.
reason_for(r, inp) := object.get(r, "reason", "") if {
	object.get(r, "reason", null) != null
}

reason_for(r, inp) := out if {
	object.get(r, "reason", null) == null
	out := sprintf("rule '%s' matched for tool '%s'", [object.get(r, "name", "?"), object.get(object.get(inp, "tool", {}), "name", "?")])
}