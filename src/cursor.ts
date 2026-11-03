import { randomBytes } from 'node:crypto';
import { ApiError } from './errors.js';

export type Resource = 'devices';
export type Position = Readonly<{ time: string; id: string }>;
export interface CursorRecord {
  readonly owner: string; readonly resource: Resource; readonly limit: number;
  readonly version: 1; readonly filters: '{}'; readonly order: 'created_at.desc,id.desc';
  readonly upper: Position; readonly after: Position; readonly issuedAt: number; readonly expiresAt: number;
}
const invalidCursor = () => new ApiError(400, 'INVALID_CURSOR');
export class CursorStore {
  // Invariante: token -> posición/contexto inmutables; índice y contadores solo
  // referencian entradas vigentes. Maps acotados: lookup/inserción O(1) esperado;
  // limpiar/contar vencimientos O(C), C<=10000. Nunca se expulsa a otro dueño.
  private readonly records = new Map<string, CursorRecord>();
  private readonly positions = new Map<string, string>();
  private readonly owners = new Map<string, number>();
  constructor(private readonly now: () => number = Date.now,
    private readonly entropy: () => Uint8Array = () => randomBytes(32),
    private readonly maximum = 10000, private readonly perOwner = 64) {}
  private key(record: Pick<CursorRecord, 'owner' | 'resource' | 'limit' | 'upper' | 'after'>): string {
    return JSON.stringify([1, record.owner, record.resource, '{}', record.limit, 'created_at.desc,id.desc',
      record.upper.time, record.upper.id, record.after.time, record.after.id]);
  }
  private sweep(): void {
    const now = this.now();
    for (const [token, record] of this.records) {
      if (record.expiresAt <= now) {
        this.records.delete(token);
        this.positions.delete(this.key(record));
        const count = (this.owners.get(record.owner) ?? 1) - 1;
        if (count) this.owners.set(record.owner, count); else this.owners.delete(record.owner);
      }
    }
  }
  resolve(token: string, owner: string, resource: Resource, limit?: number): CursorRecord {
    if (!/^c1\.[A-Za-z0-9_-]{43}$/.test(token)
      || Buffer.from(token.slice(3), 'base64url').toString('base64url') !== token.slice(3)) throw invalidCursor();
    this.sweep();
    const record = this.records.get(token);
    if (!record || record.owner !== owner || record.resource !== resource
      || (limit !== undefined && record.limit !== limit)) throw invalidCursor();
    return record;
  }
  issue(owner: string, resource: Resource, limit: number, upper: Position, after: Position): string {
    this.sweep();
    const now = this.now();
    const record: CursorRecord = Object.freeze({ owner, resource, limit, version: 1, filters: '{}',
      order: 'created_at.desc,id.desc', upper: Object.freeze({ ...upper }), after: Object.freeze({ ...after }),
      issuedAt: now, expiresAt: now + 600000 });
    const position = this.key(record);
    const existing = this.positions.get(position);
    if (existing) return existing;
    const ownCount = this.owners.get(owner) ?? 0;
    if (ownCount >= this.perOwner || this.records.size >= this.maximum) {
      let expiry = Infinity;
      for (const entry of this.records.values()) {
        if (ownCount < this.perOwner || entry.owner === owner) expiry = Math.min(expiry, entry.expiresAt);
      }
      throw new ApiError(429, 'RATE_LIMITED', { 'Retry-After': String(Math.max(1, Math.ceil((expiry - now) / 1000))) });
    }
    if (Buffer.byteLength(JSON.stringify(record)) > 2048) throw new ApiError(500, 'INTERNAL');
    for (let attempt = 0; attempt < 8; attempt += 1) {
      let bytes: Uint8Array;
      try { bytes = this.entropy(); } catch { throw new ApiError(500, 'INTERNAL'); }
      if (bytes.length !== 32) throw new ApiError(500, 'INTERNAL');
      const token = `c1.${Buffer.from(bytes).toString('base64url')}`;
      if (!this.records.has(token)) {
        // Sin await: comprobar/reutilizar/insertar es una sola sección síncrona.
        this.records.set(token, record);
        this.positions.set(position, token);
        this.owners.set(owner, ownCount + 1);
        return token;
      }
    }
    throw new ApiError(500, 'INTERNAL');
  }
  get size(): number { this.sweep(); return this.records.size; }
}

export function comparePositions(a: Position, b: Position): number {
  // UTC con seis decimales e UUID canónico: orden textual coincide con tupla SQL.
  return a.time < b.time ? -1 : a.time > b.time ? 1 : a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
}
