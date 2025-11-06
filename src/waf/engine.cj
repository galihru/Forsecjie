package forsecjie.waf

import std.collections.*
import forsecjie.core.*
import forsecjie.plugins.*

public class WAFEngine {
    private let cfg: WAFConfig
    private let alerts: AlertHeap
    private let ipLimiter: FixedWindowRateLimiter
    private let pathLimiter: FixedWindowRateLimiter
    private let sig: SignatureEngine
    private let anomaly: AnomalyEngine
    private let plugins: Array<SecurityPlugin>

    public init(cfg: WAFConfig) {
        this.cfg = cfg
        this.alerts = AlertHeap()
        this.ipLimiter = FixedWindowRateLimiter(cfg.ipRate)
        this.pathLimiter = FixedWindowRateLimiter(cfg.pathRate)
        this.sig = SignatureEngine()
        this.anomaly = AnomalyEngine()
        this.plugins = Array<SecurityPlugin>()
        this.plugins.add(BotDetectionPlugin())
        this.plugins.add(GeoIpPlugin())
        this.plugins.add(JwtPlugin("Authorization"))
    }

    public func evaluate(ctx: RequestContext, nowMs: Int64): Decision {
        let alertsList = Array<Alert>()
        var score: Int64 = 0
        let reasons = Array<String>()

        let ipKey = ctx.ip
        let pathKey = ctx.method + ":" + ctx.path

        let ipOk = this.ipLimiter.allow(ipKey, nowMs)
        if (!ipOk) {
            let id1 = this.alerts.nextAlertId()
            let a1 = Alert(id1, nowMs, AlertLevel.High, 40, ctx.ip, ctx.method, ctx.path, "RL_IP", "Rate limit exceeded by ip")
            this.alerts.push(a1)
            alertsList.add(a1)
            score = score + 40
            reasons.add("RL_IP")
        }

        let pathOk = this.pathLimiter.allow(pathKey, nowMs)
        if (!pathOk) {
            let id2 = this.alerts.nextAlertId()
            let a2 = Alert(id2, nowMs, AlertLevel.Medium, 30, ctx.ip, ctx.method, ctx.path, "RL_PATH", "Rate limit exceeded by path")
            this.alerts.push(a2)
            alertsList.add(a2)
            score = score + 30
            reasons.add("RL_PATH")
        }

        let uri = ctx.path + "?" + ctx.query
        let sigMatches = this.sig.inspect(uri, ctx.body)
        for (m in sigMatches) {
            let id3 = this.alerts.nextAlertId()
            let lv3 = this.chooseLevel(m.score)
            let a3 = Alert(id3, nowMs, lv3, m.score, ctx.ip, ctx.method, ctx.path, m.ruleId, m.message)
            this.alerts.push(a3)
            alertsList.add(a3)
            score = score + m.score
            reasons.add(m.ruleId)
        }

        let anomalyMatches = this.anomaly.analyze(ctx.path, ctx.query, ctx.body)
        for (am in anomalyMatches) {
            let id4 = this.alerts.nextAlertId()
            let lv4 = this.chooseLevel(am.score)
            let a4 = Alert(id4, nowMs, lv4, am.score, ctx.ip, ctx.method, ctx.path, "ANOMALY", am.reason)
            this.alerts.push(a4)
            alertsList.add(a4)
            score = score + am.score
            reasons.add(am.reason)
        }

        for (p in this.plugins) {
            let pa = p.evaluate(ctx, nowMs)
            for (a in pa) {
                let withId = Alert(this.alerts.nextAlertId(), a.createdAtMs, a.level, a.score, a.sourceIp, a.method, a.path, a.ruleId, a.message)
                this.alerts.push(withId)
                alertsList.add(withId)
                score = score + withId.score
                reasons.add(withId.ruleId)
            }
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
