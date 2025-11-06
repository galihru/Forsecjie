package forsecjie.rules

import std.collections.*

public func loadRceRules(): Array<RulePattern> {
    let r = Array<RulePattern>()
    r.add(RulePattern(";wget ", 50, "SIG_RCE_WGET", "Command injection wget"))
    r.add(RulePattern(";curl ", 50, "SIG_RCE_CURL", "Command injection curl"))
    r.add(RulePattern("bash -c", 50, "SIG_RCE_BASH", "Command injection bash"))
    r.add(RulePattern("system(", 45, "SIG_RCE_SYSTEM", "system() call"))
    r.add(RulePattern("exec(", 45, "SIG_RCE_EXEC", "exec() call"))
    r
}
