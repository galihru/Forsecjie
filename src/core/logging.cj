package forsecjie.core

import stdx.log.*

public class Log {
    private let logger: Logger

    public init() {
        this.logger = getGlobalLogger([])
        this.logger.level = LogLevel.INFO
    }

    public func info(msg: String): Unit {
        this.logger.info(msg, [])
    }

    public func warn(msg: String): Unit {
        this.logger.warn(msg, [])
    }

    public func error(msg: String): Unit {
        this.logger.error(msg, [])
    }

    public func infoWithFields(msg: String, fields: Array<(String, String)>): Unit {
        this.logger.info(msg, fields)
    }

    public func warnWithFields(msg: String, fields: Array<(String, String)>): Unit {
        this.logger.warn(msg, fields)
    }

    public func errorWithFields(msg: String, fields: Array<(String, String)>): Unit {
        this.logger.error(msg, fields)
    }
}
