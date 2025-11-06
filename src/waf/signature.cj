package forsecjie.waf

import std.collections.*
import forsecjie.rules.*

public struct SignatureMatch {
    public let score: Int64
    public let ruleId: String
    public let message: String
}

public class SignatureEngine {
    private let patterns: Array<RulePattern>

    public init() {
        let all = Array<RulePattern>()
        merge(all, loadSqliRules())
        merge(all, loadXssRules())
        merge(all, loadRceRules())
        merge(all, loadPathTraversalRules())
        merge(all, loadSsrfRules())
        merge(all, loadLog4shellRules())
        this.patterns = all
    }

    private func merge(target: Array<RulePattern>, src: Array<RulePattern>): Unit {
        for (p in src) {
            target.add(p)
        }
    }

    public func inspect(uri: String, body: String): Array<SignatureMatch> {
        let matches = Array<SignatureMatch>()
        let u = uri.toLowerCase()
        let b = body.toLowerCase()
        for (p in this.patterns) {
            if (u.contains(p.token) || b.contains(p.token)) {
                matches.add(SignatureMatch(p.score, p.ruleId, p.message))
            }
        }
        matches
    }
}
