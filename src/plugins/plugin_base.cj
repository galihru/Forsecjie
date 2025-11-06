package forsecjie.plugins

import std.collections.*
import forsecjie.core.*

public abstract class SecurityPlugin {
    public abstract func name(): String
    public abstract func evaluate(ctx: RequestContext, nowMs: Int64): Array<Alert>
}
