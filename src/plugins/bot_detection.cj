package forsecjie.plugins

import std.collections.*
import forsecjie.core.*

public class BotDetectionPlugin extends SecurityPlugin {
    public override func name(): String {
        "bot-detection"
    }

    public override func evaluate(ctx: RequestContext, nowMs: Int64): Array<Alert> {
        let alerts = Array<Alert>()
        let path = ctx.path.toLowerCase()
        if (path.contains("/wp-admin") || path.contains("/wp-login.php") || path.contains("/phpmyadmin") || path.contains("/.git/")) {
            let a = Alert(nowMs, nowMs, AlertLevel.Medium, 25, ctx.ip, ctx.method, ctx.path, "BOT_SCAN", "Common scanner/probe path")
            alerts.add(a)
        }
        alerts
    }
}
