package forsecjie.rules

import std.collections.*

public func loadLog4shellRules(): Array<RulePattern> {
    let r = Array<RulePattern>()
    r.add(RulePattern("${jndi:", 60, "SIG_LOG4SHELL_JNDI", "JNDI injection pattern"))
    r.add(RulePattern("${jndi:ldap", 60, "SIG_LOG4SHELL_LDAP", "Log4Shell LDAP payload"))
    r.add(RulePattern("${jndi:rmi", 55, "SIG_LOG4SHELL_RMI", "RMI JNDI payload"))
    r.add(RulePattern("${jndi:dns", 55, "SIG_LOG4SHELL_DNS", "DNS JNDI payload"))
    r
}
