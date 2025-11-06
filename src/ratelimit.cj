package forsecjie

import std.collections.*

public struct RateBucket {
    public var windowStartMs: Int64
    public var count: Int64
}

public class FixedWindowRateLimiter {
    private let limit: Int64
    private let windowMs: Int64
    private let buckets: HashMap<String, RateBucket>

    public init(limit: Int64, windowMs: Int64) {
        this.limit = limit
        this.windowMs = windowMs
        this.buckets = HashMap<String, RateBucket>()
    }

    public func allow(key: String, nowMs: Int64): Bool {
        if (let Some(b0) <- this.buckets.get(key)) {
            var bucket = b0
            if (nowMs - bucket.windowStartMs >= this.windowMs) {
                bucket.windowStartMs = nowMs
                bucket.count = 0
            }
            if (bucket.count < this.limit) {
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
