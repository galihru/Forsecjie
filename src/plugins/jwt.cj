package forsecjie.plugins

import std.collections.*
import forsecjie.core.*
import stdx.encoding.*

public class JwtPlugin extends SecurityPlugin {
    private let headerName: String

    public init(headerName: String) {
        this.headerName = headerName
    }

    public override func name(): String {
        "jwt"
    }

    public override func evaluate(ctx: RequestContext, nowMs: Int64): Array<Alert> {
        let alerts = Array<Alert>()
        if (!ctx.headers.containsKey(this.headerName)) {
            return alerts
        }
        let raw = ctx.headers.get(this.headerName)
        if (!raw.startsWith("Bearer ")) {
            return alerts
        }
        let token = raw.substring(7, raw.length)
        let parts = token.split(".")
        if (parts.size != 3) {
            let a = Alert(nowMs, nowMs, AlertLevel.Medium, 30, ctx.ip, ctx.method, ctx.path, "JWT_FORMAT", "Invalid JWT format")
            alerts.add(a)
            return alerts
        }
        alerts
    }
}
