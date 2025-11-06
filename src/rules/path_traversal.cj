package forsecjie.rules

import std.collections.*

public func loadPathTraversalRules(): Array<RulePattern> {
    let r = Array<RulePattern>()
    r.add(RulePattern("../", 30, "SIG_PATH_DOTDOT", "Directory traversal"))
    r.add(RulePattern("..\\", 30, "SIG_PATH_DOTDOT_WIN", "Directory traversal"))
    r.add(RulePattern("/etc/passwd", 40, "SIG_PATH_ETC_PASSWD", "Linux passwd access"))
    r.add(RulePattern("c:\\windows", 40, "SIG_PATH_WINDOWS", "Windows system path"))
    r
}
