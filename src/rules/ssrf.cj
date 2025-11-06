package forsecjie.rules

import std.collections.*

public func loadSsrfRules(): Array<RulePattern> {
    let r = Array<RulePattern>()
    r.add(RulePattern("169.254.169.254", 45, "SIG_SSRF_IMDS", "Cloud metadata SSRF"))
    r.add(RulePattern("metadata.google.internal", 45, "SIG_SSRF_GCE", "GCE metadata SSRF"))
    r.add(RulePattern("latest/meta-data", 35, "SIG_SSRF_META", "Metadata path SSRF"))
    r
}
