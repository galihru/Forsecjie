package forsecjie.core

public struct RateLimitConfig {
    public let limit: Int64
    public let windowMs: Int64
}

public struct WAFConfig {
    public let ipRate: RateLimitConfig
    public let pathRate: RateLimitConfig
    public let blockScoreThreshold: Int64
}

public func defaultConfig(): WAFConfig {
    let ipRate = RateLimitConfig(300, 60000)
    let pathRate = RateLimitConfig(600, 60000)
    WAFConfig(ipRate, pathRate, 80)
}
