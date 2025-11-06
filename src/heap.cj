package forsecjie

import std.collections.*

public class AlertHeap {
    private var data: Array<Alert>
    private var nextId: Int64

    public init() {
        this.data = Array<Alert>()
        this.nextId = 1
    }

    public func nextAlertId(): Int64 {
        let id = this.nextId
        this.nextId = this.nextId + 1
        id
    }

    private func priority(level: AlertLevel): Int32 {
        match (level) {
            case AlertLevel.Info => 0
            case AlertLevel.Low => 1
            case AlertLevel.Medium => 2
            case AlertLevel.High => 3
            case AlertLevel.Critical => 4
        }
    }

    private func more(a: Alert, b: Alert): Bool {
        let pa = priority(a.level)
        let pb = priority(b.level)
        if (pa != pb) {
            return pa > pb
        }
        if (a.score != b.score) {
            return a.score > b.score
        }
        a.createdAtMs < b.createdAtMs
    }

    public func push(a: Alert): Unit {
        this.data.add(a)
        var i: Int64 = this.data.size - 1
        while (i > 0) {
            let p: Int64 = (i - 1) / 2
            if (more(this.data[p], this.data[i])) {
                break
            }
            let t = this.data[p]
            this.data[p] = this.data[i]
            this.data[i] = t
            i = p
        }
    }

    public func pop(): Option<Alert> {
        if (this.data.size == 0) {
            return None
        }
        let top = this.data[0]
        let lastIndex: Int64 = this.data.size - 1
        if (lastIndex == 0) {
            this.data.clear()
        } else {
            this.data[0] = this.data[lastIndex]
            this.data.remove(lastIndex)
            siftDown(0)
        }
        Some(top)
    }

    public func peek(): Option<Alert> {
        if (this.data.size == 0) {
            return None
        }
        Some(this.data[0])
    }

    private func siftDown(start: Int64): Unit {
        var i = start
        let n = this.data.size
        while (true) {
            let left = 2 * i + 1
            let right = 2 * i + 2
            var best = i
            if (left < n && more(this.data[left], this.data[best])) {
                best = left
            }
            if (right < n && more(this.data[right], this.data[best])) {
                best = right
            }
            if (best == i) {
                break
            }
            let t = this.data[i]
            this.data[i] = this.data[best]
            this.data[best] = t
            i = best
        }
    }

    public func size(): Int64 {
        this.data.size
    }
}
