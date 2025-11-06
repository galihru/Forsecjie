package forsecjie.rules

import std.collections.*

public func loadXssRules(): Array<RulePattern> {
    let r = Array<RulePattern>()
    r.add(RulePattern("<script", 35, "SIG_XSS_SCRIPT", "Script tag in input"))
    r.add(RulePattern("javascript:", 30, "SIG_XSS_JS_PROTO", "Javascript URL"))
    r.add(RulePattern("onerror=", 30, "SIG_XSS_ONERROR", "Inline handler onerror"))
    r.add(RulePattern("onload=", 25, "SIG_XSS_ONLOAD", "Inline handler onload"))
    r.add(RulePattern("alert(", 25, "SIG_XSS_ALERT", "Alert pattern"))
    r
}
