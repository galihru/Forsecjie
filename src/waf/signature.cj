package forsecjie.waf

import std.collections.*

public struct SignatureMatch {
    public let score: Int64
    public let ruleId: String
    public let message: String
}

public class SignatureEngine {
    private let sqlTokens: Array<String>
    private let xssTokens: Array<String>
    private let pathTokens: Array<String>
    private let rceTokens: Array<String>
    private let ssrfTokens: Array<String>
    private let log4jTokens: Array<String>

    public init() {
        this.sqlTokens = [
            "union select",
            " or 1=1",
            " and 1=1",
            "' or '1'='1",
            "\" or \"1\"=\"1",
            "sleep(",
            "benchmark(",
            "information_schema",
            "load_file(",
            " into outfile "
        ]
        this.xssTokens = [
            "<script",
            "onerror=",
            "onload=",
            "javascript:",
            "alert(",
            "svg on"
        ]
        this.pathTokens = [
            "../",
            "..\\",
            "/etc/passwd",
            "c:\\windows",
            "/..;/"
        ]
        this.rceTokens = [
            ";wget ",
            ";curl ",
            ";powershell ",
            "system(",
            "exec(",
            "bash -c",
            "`whoami`"
        ]
        this.ssrfTokens = [
            "169.254.169.254",
            "metadata.google.internal",
            "latest/meta-data",
            "http://169.254.169.254",
            "http://metadata.google.internal"
        ]
        this.log4jTokens = [
            "${jndi:",
            "${jndi:ldap",
            "${jndi:dns",
            "${jndi:rmi"
        ]
    }

    public func inspect(uri: String, body: String): Array<SignatureMatch> {
        let matches = Array<SignatureMatch>()
        let u = uri.toLowerCase()
        let b = body.toLowerCase()

        for (t in this.sqlTokens) {
            if (u.contains(t) || b.contains(t)) {
                matches.add(SignatureMatch(40, "SIG_SQLI", "SQL injection pattern " + t))
            }
        }
        for (t in this.xssTokens) {
            if (u.contains(t) || b.contains(t)) {
                matches.add(SignatureMatch(35, "SIG_XSS", "XSS pattern " + t))
            }
        }
        for (t in this.pathTokens) {
            if (u.contains(t) || b.contains(t)) {
                matches.add(SignatureMatch(30, "SIG_PATH", "Path traversal pattern " + t))
            }
        }
        for (t in this.rceTokens) {
            if (u.contains(t) || b.contains(t)) {
                matches.add(SignatureMatch(50, "SIG_RCE", "Remote code execution pattern " + t))
            }
        }
        for (t in this.ssrfTokens) {
            if (u.contains(t) || b.contains(t)) {
                matches.add(SignatureMatch(45, "SIG_SSRF", "SSRF pattern " + t))
            }
        }
        for (t in this.log4jTokens) {
            if (u.contains(t) || b.contains(t)) {
                matches.add(SignatureMatch(60, "SIG_LOG4SHELL", "Log4Shell-style payload"))
            }
        }

        matches
    }
}
