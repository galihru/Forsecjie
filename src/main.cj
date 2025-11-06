package forsecjie

import stdx.net.http.*
import stdx.log.*

let wafEngine = WAFEngine()

func handle(ctx: HttpContext): Unit {
    let req = ctx.request
    let path = req.path
    let method = req.method
    let query = req.query
    let ip = req.headers.getFirst("X-Forwarded-For")
    let body = ""
    let nowMs = System.currentTimeMillis()
    let rc = RequestContext(ip, method, path, query, body)
    let decision = wafEngine.evaluate(rc, nowMs)
    let logger = getGlobalLogger([])

    if (decision.action == DecisionAction.Block) {
        logger.warn("Forsecjie block", [("ip", ip), ("path", path), ("score", decision.score.toString()), ("reason", decision.reason)])
        ctx.responseBuilder.status(decision.status).body("Blocked by Forsecjie")
    } else {
        logger.info("Forsecjie allow", [("ip", ip), ("path", path), ("score", decision.score.toString())])
        ctx.responseBuilder.status(200).body("OK")
    }
}

main() {
    let logger = getGlobalLogger([])
    logger.level = LogLevel.INFO
    let server = ServerBuilder()
        .addr("0.0.0.0")
        .port(8080)
        .build()
    server.distributor.register("/", {ctx => handle(ctx)})
    server.serve()
}
