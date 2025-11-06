package forsecjie.rules

import std.collections.*

public func loadSqliRules(): Array<RulePattern> {
    let r = Array<RulePattern>()
    r.add(RulePattern("union select", 40, "SIG_SQLI_UNION", "SQL injection UNION SELECT"))
    r.add(RulePattern(" or 1=1", 35, "SIG_SQLI_BOOL_OR", "SQL injection boolean OR"))
    r.add(RulePattern(" and 1=1", 30, "SIG_SQLI_BOOL_AND", "SQL injection boolean AND"))
    r.add(RulePattern("' or '1'='1", 40, "SIG_SQLI_CLASSIC", "SQL injection classic pattern"))
    r.add(RulePattern(" information_schema", 35, "SIG_SQLI_INFO_SCHEMA", "System schema access"))
    r.add(RulePattern(" load_file(", 45, "SIG_SQLI_LOAD_FILE", "File read function"))
    r.add(RulePattern(" into outfile ", 45, "SIG_SQLI_OUTFILE", "Write file via SQL"))
    r.add(RulePattern(" sleep(", 35, "SIG_SQLI_TIME", "Time based injection"))
    r
}
