package forsecjie.http

import stdx.net.http.*
import forsecjie.core.*
import forsecjie.waf.*

public class ForsecjieServer {
    private let engine: WAFEngine

    public init(engine: WAFEngine) {
        this.engine = engine
    }

    public func start(): Unit {
        let server = ServerBuilder()
            .addr("0.0.0.0")
            .port(8080)
            .build()
        server.distributor.register("/", { ctx => this.handle(ctx) })
        server.serve()
    }

    private func handle(ctx: HttpContext): Unit {
        let req = ctx.request
        let ip = req.headers.getFirst("X-Forwarded-For")
        let method = req.method
        let path = req.path
        let query = req.query
        let body = ""
        let nowMs: Int64 = 0
        let rc = RequestContext(ip, method, path, query, body)
        let decision = this.engine.evaluate(rc, nowMs)
        if (decision.action == DecisionAction.Block) {
            ctx.responseBuilder.status(decision.status).body("Blocked by Forsecjie: " + decision.reason)
        } else {
            ctx.responseBuilder.status(200).body("OK")
        }
    }
}
