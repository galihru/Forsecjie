package forsecjie.waf

import std.collections.*
import forsecjie.core.*

public struct RateBucket {
    public var windowStartMs: Int64
    public var count: Int64
}

public class FixedWindowRateLimiter {
    private let cfg: RateLimitConfig
    private let buckets: HashMap<String, RateBucket>

    public init(cfg: RateLimitConfig) {
        this.cfg = cfg
        this.buckets = HashMap<String, RateBucket>()
    }

    public func allow(key: String, nowMs: Int64): Bool {
        if (let Some(prev) <- this.buckets.get(key)) {
            var bucket = prev
            if (nowMs - bucket.windowStartMs >= this.cfg.windowMs) {
                bucket.windowStartMs = nowMs
                bucket.count = 0
            }
            if (bucket.count < this.cfg.limit) {
                bucket.count = bucket.count + 1
                this.buckets.put(key, bucket)
                return true
            } else {
                this.buckets.put(key, bucket)
                return false
            }
        } else {
            let bucket = RateBucket(nowMs, 1)
            this.buckets.put(key, bucket)
            return true
        }
    }
}
