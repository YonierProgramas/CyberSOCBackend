import { ApiError } from './errors.js';

type Bucket = { tokens: number; at: number; capacity: number; perMinute: number };
export class RateLimits {
  // Invariante: una clave conserva su capacidad/tasa y saldo [0,capacidad].
  // Map acotado a 10 000; búsqueda/inserción O(1) esperada, limpieza O(B).
  private readonly buckets = new Map<string, Bucket>();
  constructor(private readonly now: () => number = Date.now, private readonly maximum = 10000) {}
  consume(key: string, capacity: number): void {
    const now = this.now();
    for (const [name, bucket] of this.buckets) if (now - bucket.at >= 120000) this.buckets.delete(name);
    let bucket = this.buckets.get(key);
    if (!bucket) {
      if (this.buckets.size >= this.maximum) throw new ApiError(429, 'RATE_LIMITED', { 'Retry-After': '120' });
      bucket = { tokens: capacity, capacity, perMinute: capacity, at: now };
      this.buckets.set(key, bucket);
    }
    bucket.tokens = Math.min(bucket.capacity, bucket.tokens + Math.max(0, now - bucket.at) * bucket.perMinute / 60000);
    bucket.at = now;
    if (bucket.tokens < 1) throw new ApiError(429, 'RATE_LIMITED', {
      'Retry-After': String(Math.max(1, Math.ceil((1 - bucket.tokens) * 60 / bucket.perMinute))),
    });
    bucket.tokens -= 1;
  }
  get size(): number { return this.buckets.size; }
}
