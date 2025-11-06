package forsecjie

import std.collections.*

public class WAFEngine {
    private let alerts: AlertHeap
    private let rateByIp: FixedWindowRateLimiter
    private let rateByPath: FixedWindowRateLimiter
    private let sig: SignatureEngine
    private let anomaly: AnomalyEngine
    private let blockThreshold: Int64

    public init() {
        this.alerts = AlertHeap()
        this.rateByIp = FixedWindowRateLimiter(300, 60000)
        this.rateByPath = FixedWindowRateLimiter(600, 60000)
        this.sig = SignatureEngine()
        this.anomaly = AnomalyEngine()
        this.blockThreshold = 80
    }

    public func evaluate(ctx: RequestContext, nowMs: Int64): Decision {
        let alertList = Array<Alert>()
        var score: Int64 = 0
        let reasons = Array<String>()

        let ipKey = ctx.ip
        let pathKey = ctx.method + ":" + ctx.path

        let ipAllowed = this.rateByIp.allow(ipKey, nowMs)
        let pathAllowed = this.rateByPath.allow(pathKey, nowMs)

        if (!ipAllowed) {
            let id = this.alerts.nextAlertId()
            let a = Alert(id, nowMs, AlertLevel.High, 50, ctx.ip, ctx.method, ctx.path, "RL_IP", "Rate limit exceeded by ip")
            this.alerts.push(a)
            alertList.add(a)
            score = score + 50
            reasons.add("RL_IP")
        }

        if (!pathAllowed) {
            let id = this.alerts.nextAlertId()
            let a = Alert(id, nowMs, AlertLevel.Medium, 30, ctx.ip, ctx.method, ctx.path, "RL_PATH", "Rate limit exceeded by path")
            this.alerts.push(a)
            alertList.add(a)
            score = score + 30
            reasons.add("RL_PATH")
        }

        let uri = ctx.path + "?" + ctx.query
        let sigMatches = this.sig.inspect(uri, ctx.body)
        for (m in sigMatches) {
            let id = this.alerts.nextAlertId()
            let level = chooseLevel(m.score)
            let a = Alert(id, nowMs, level, m.score, ctx.ip, ctx.method, ctx.path, m.ruleId, m.message)
            this.alerts.push(a)
            alertList.add(a)
            score = score + m.score
            reasons.add(m.ruleId)
        }

        let anomalyMatches = this.anomaly.analyze(ctx.path, ctx.query, ctx.body)
        for (as in anomalyMatches) {
            let id = this.alerts.nextAlertId()
            let level = chooseLevel(as.score)
            let a = Alert(id, nowMs, level, as.score, ctx.ip, ctx.method, ctx.path, "ANOMALY", as.reason)
            this.alerts.push(a)
            alertList.add(a)
            score = score + as.score
            reasons.add(as.reason)
        }

        var action = DecisionAction.Allow
        var status: Int32 = 200
        var reason = "ok"

        if (score >= this.blockThreshold) {
            action = DecisionAction.Block
            status = 403
            reason = joinReasons(reasons)
        }

        Decision(action, status, reason, score, alertList)
    }

    private func chooseLevel(score: Int64): AlertLevel {
        if (score >= 60) {
            AlertLevel.Critical
        } else if (score >= 40) {
            AlertLevel.High
        } else if (score >= 25) {
            AlertLevel.Medium
        } else if (score >= 10) {
            AlertLevel.Low
        } else {
            AlertLevel.Info
        }
    }

    private func joinReasons(reasons: Array<String>): String {
        if (reasons.size == 0) {
            return "ok"
        }
        var s = reasons[0]
        var i: Int64 = 1
        while (i < reasons.size) {
            s = s + "," + reasons[i]
            i = i + 1
        }
        s
    }
}
