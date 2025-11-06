package forsecjie

import forsecjie.core.*
import forsecjie.waf.*
import forsecjie.http.*

public func main(): Int32 {
    let cfg = defaultConfig()
    let engine = WAFEngine(cfg)
    let server = ForsecjieServer(engine)
    server.start()
    0
}
