package forsecjie.waf

import std.collections.*
import forsecjie.core.*

public class WAFEngine {
    private let cfg: WAFConfig
    private let alerts: AlertHeap
    private let ipLimiter: FixedWindowRateLimiter
    private let pathLimiter: FixedWindowRateLimiter
    private let sig: SignatureEngine
    private let anomaly: AnomalyEngine

    public init(cfg: WAFConfig) {
        this.cfg = cfg
        this.alerts = AlertHeap()
        this.ipLimiter = FixedWindowRateLimiter(cfg.ipRate)
        this.pathLimiter = FixedWindowRateLimiter(cfg.pathRate)
        this.sig = SignatureEngine()
        this.anomaly = AnomalyEngine()
    }

    public func evaluate(ctx: RequestContext, nowMs: Int64): Decision {
        let alertsList = Array<Alert>()
        var score: Int64 = 0
        let reasons = Array<String>()

        let ipKey = ctx.ip
        let pathKey = ctx.method + ":" + ctx.path

        let ipOk = this.ipLimiter.allow(ipKey, nowMs)
        if (!ipOk) {
            let id = this.alerts.nextAlertId()
            let a = Alert(id, nowMs, AlertLevel.High, 40, ctx.ip, ctx.method, ctx.path, "RL_IP", "Rate limit exceeded by ip")
            this.alerts.push(a)
            alertsList.add(a)
            score = score + 40
            reasons.add("RL_IP")
        }

        let pathOk = this.pathLimiter.allow(pathKey, nowMs)
        if (!pathOk) {
            let id = this.alerts.nextAlertId()
            let a = Alert(id, nowMs, AlertLevel.Medium, 30, ctx.ip, ctx.method, ctx.path, "RL_PATH", "Rate limit exceeded by path")
            this.alerts.push(a)
            alertsList.add(a)
            score = score + 30
            reasons.add("RL_PATH")
        }

        let uri = ctx.path + "?" + ctx.query
        let sigMatches = this.sig.inspect(uri, ctx.body)
        for (m in sigMatches) {
            let id = this.alerts.nextAlertId()
            let level = this.chooseLevel(m.score)
            let a = Alert(id, nowMs, level, m.score, ctx.ip, ctx.method, ctx.path, m.ruleId, m.message)
            this.alerts.push(a)
            alertsList.add(a)
            score = score + m.score
            reasons.add(m.ruleId)
        }

        let anomalyMatches = this.anomaly.analyze(ctx.path, ctx.query, ctx.body)
        for (as in anomalyMatches) {
            let id = this.alerts.nextAlertId()
            let level = this.chooseLevel(as.score)
            let a = Alert(id, nowMs, level, as.score, ctx.ip, ctx.method, ctx.path, "ANOMALY", as.reason)
            this.alerts.push(a)
            alertsList.add(a)
            score = score + as.score
            reasons.add(as.reason)
        }

        var action = DecisionAction.Allow
        var status: Int32 = 200
        var reason = "ok"

        if (score >= this.cfg.blockScoreThreshold) {
            action = DecisionAction.Block
            status = 403
            reason = this.joinReasons(reasons)
        }

        Decision(action, status, reason, score, alertsList)
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

    public func popTopAlert(): Option<Alert> {
        this.alerts.pop()
    }
}
