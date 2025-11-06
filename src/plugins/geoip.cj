package forsecjie.plugins

import std.collections.*
import forsecjie.core.*

public class GeoIpPlugin extends SecurityPlugin {
    public override func name(): String {
        "geoip"
    }

    private func regionRisk(ip: String): Int64 {
        if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("172.16.")) {
            return 0
        }
        10
    }

    public override func evaluate(ctx: RequestContext, nowMs: Int64): Array<Alert> {
        let alerts = Array<Alert>()
        let risk = regionRisk(ctx.ip)
        if (risk > 0) {
            let a = Alert(nowMs, nowMs, AlertLevel.Low, risk, ctx.ip, ctx.method, ctx.path, "GEO_GENERIC", "Generic external region access")
            alerts.add(a)
        }
        alerts
    }
}
