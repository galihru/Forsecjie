package forsecjie

import std.collections.*

public enum AlertLevel {
    Info
    Low
    Medium
    High
    Critical
}

public enum DecisionAction {
    Allow
    Block
}

public struct Alert {
    public let id: Int64
    public let createdAtMs: Int64
    public let level: AlertLevel
    public let score: Int64
    public let sourceIp: String
    public let method: String
    public let path: String
    public let ruleId: String
    public let message: String
}

public struct Decision {
    public let action: DecisionAction
    public let status: Int32
    public let reason: String
    public let score: Int64
    public let alerts: Array<Alert>
}

public struct RequestContext {
    public let ip: String
    public let method: String
    public let path: String
    public let query: String
    public let body: String
}
