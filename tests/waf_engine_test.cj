package forsecjie.tests

import forsecjie.core.*
import forsecjie.waf.*
import std.collections.*

public func testBlockOnHighScore(): Bool {
    let cfg = WAFConfig(RateLimitConfig(1, 60000), RateLimitConfig(1, 60000), 10)
    let engine = WAFEngine(cfg)
    let headers = HashMap<String, String>()
    let ctx = RequestContext("1.2.3.4", "GET", "/../../etc/passwd", "", "", headers)
    let d = engine.evaluate(ctx, 0)
    d.action == DecisionAction.Block
}

public func main(): Int32 {
    if (!testBlockOnHighScore()) {
        return 1
    }
    0
}
