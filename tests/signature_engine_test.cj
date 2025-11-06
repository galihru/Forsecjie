package forsecjie.tests

import forsecjie.waf.*

public func testDetectSql(): Bool {
    let sig = SignatureEngine()
    let matches = sig.inspect("/api?q=1 union select password from users", "")
    matches.size > 0
}

public func main(): Int32 {
    if (!testDetectSql()) {
        return 1
    }
    0
}
