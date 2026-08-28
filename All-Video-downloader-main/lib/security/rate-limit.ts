import net from "net"

interface Bucket {
  count: number
  resetAt: number
}

const buckets = new Map<string, Bucket>()

const MAX_BUCKETS = (() => {
  const n = parseInt(process.env.RATE_LIMIT_MAX_BUCKETS || "10000", 10)
  return Number.isFinite(n) && n > 0 ? n : 10000
})()

function evictIfFull(now: number): void {
  if (buckets.size < MAX_BUCKETS) return
  for (const [key, b] of buckets) {
    if (buckets.size < MAX_BUCKETS) break
    if (b.resetAt <= now) buckets.delete(key)
  }
  while (buckets.size >= MAX_BUCKETS) {
    const oldestKey = buckets.keys().next().value
    if (oldestKey === undefined) break
    buckets.delete(oldestKey)
  }
}

export function checkRateLimit(key: string, limit: number, windowMs: number): boolean {
  const now = Date.now()
  const existing = buckets.get(key)
  if (!existing || existing.resetAt <= now) {
    evictIfFull(now)
    buckets.set(key, { count: 1, resetAt: now + windowMs })
    return true
  }
  if (existing.count >= limit) return false
  existing.count += 1
  return true
}

setInterval(() => {
  const now = Date.now()
  for (const [key, b] of buckets) if (b.resetAt <= now) buckets.delete(key)
}, 5 * 60 * 1000).unref?.()

export const __testing = { buckets, MAX_BUCKETS }

const TRUST_PROXY = process.env.TRUST_PROXY === "true"
const TRUSTED_PROXY_HOPS = (() => {
  const n = parseInt(process.env.TRUSTED_PROXY_HOPS || "1", 10)
  return Number.isFinite(n) && n > 0 ? n : 1
})()

function isValidIp(value: string): boolean {
  return net.isIP(value.trim()) !== 0
}

export function clientKey(request: Request): string {
  if (!TRUST_PROXY) return "unknown"
  const fwd = request.headers.get("x-forwarded-for")
  if (!fwd) return "unknown"
  const parts = fwd
    .split(",")
    .map((p) => p.trim())
    .filter(Boolean)
  if (!parts.length) return "unknown"
  const index = parts.length - TRUSTED_PROXY_HOPS
  const candidate = parts[index >= 0 ? index : 0]
  if (!isValidIp(candidate)) return "unknown"
  return candidate
}

class ConcurrencyGuard {
  private active = 0
  constructor(private readonly max: number) {}

  tryAcquire(): boolean {
    if (this.active >= this.max) return false
    this.active += 1
    return true
  }
  release() {
    this.active = Math.max(0, this.active - 1)
  }
  get current() {
    return this.active
  }
}

// FIX: Reduced from 4/2 to 1/1 for Render Free (512MB RAM, 0.1 CPU)
export const extractGuard = new ConcurrencyGuard(1)
export const downloadGuard = new ConcurrencyGuard(1)
