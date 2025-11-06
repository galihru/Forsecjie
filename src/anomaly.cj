package forsecjie

import std.collections.*

public struct AnomalyScore {
    public let score: Int64
    public let reason: String
}

public class AnomalyEngine {
    public init() {
    }

    public func analyze(path: String, query: String, body: String): Array<AnomalyScore> {
        let result = Array<AnomalyScore>()

        let pathLen = path.length
        if (pathLen > 2048) {
            result.add(AnomalyScore(30, "Path too long"))
        }

        let bodyLen = body.length
        if (bodyLen > 512000) {
            result.add(AnomalyScore(40, "Body too large"))
        }

        let combined = path + "?" + query + body
        let specials = countSpecial(combined)
        if (specials >= 32) {
            result.add(AnomalyScore(25, "High special-char density"))
        }

        result
    }

    private func countSpecial(s: String): Int64 {
        var c: Int64 = 0
        var i: Int64 = 0
        while (i < s.length) {
            let ch = s.charAt(i)
            if (ch == '\'' || ch == '"' || ch == '<' || ch == '>' ||
                ch == ';' || ch == '$' || ch == '{' || ch == '}' ||
                ch == '(' || ch == ')' || ch == '\\') {
                c = c + 1
            }
            i = i + 1
        }
        c
    }
}
