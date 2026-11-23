/** Synchronous transaction boundary; no delete/reset/prune operation. */
import { canonical, digest, requireThat, validateBlock, ZERO, type Body } from './protocol';

export interface SQL {
  exec(query: string, ...args: any[]): { toArray(): any[] };
}
export interface Storage {
  sql: SQL;
  transactionSync<T>(callback: () => T): T;
  sync(): Promise<void>;
}
export class ChainStore {
  constructor(readonly storage: Storage, readonly budget: number) {
    requireThat(Number.isSafeInteger(budget) && budget >= 8192 && budget <= 1024 ** 3);
    storage.sql.exec('CREATE TABLE IF NOT EXISTS blocks(height INTEGER PRIMARY KEY, digest TEXT NOT NULL, data TEXT NOT NULL, bytes INTEGER NOT NULL)');
    storage.sql.exec('CREATE TABLE IF NOT EXISTS chain(id INTEGER PRIMARY KEY CHECK(id=1), height INTEGER NOT NULL, digest TEXT NOT NULL, bytes INTEGER NOT NULL)');
  }
  headMeta() {
    return this.storage.sql.exec('SELECT height,digest,bytes FROM chain WHERE id=1').toArray()[0] ??
      { height: 0, digest: ZERO, bytes: 0 };
  }
  async get(height: number, stream: string): Promise<Body> {
    const row = this.storage.sql.exec('SELECT digest,data FROM blocks WHERE height=?', height).toArray()[0];
    requireThat(row);
    const block = JSON.parse(row.data);
    await validateBlock(block);
    requireThat(block.stream === stream && block.height === height && await digest(block) === row.digest);
    return block;
  }
  async head(stream: string): Promise<Body | null> {
    const meta = this.headMeta();
    if (!meta.height) return null;
    const block = await this.get(meta.height, stream);
    requireThat(await digest(block) === meta.digest);
    return block;
  }
  async append(block: Body) {
    await validateBlock(block);
    const data = canonical(block), hash = await digest(block), size = new TextEncoder().encode(data).length;
    this.storage.transactionSync(() => {
      const existing = this.storage.sql.exec('SELECT digest,data FROM blocks WHERE height=?', block.height).toArray()[0];
      if (existing) {
        requireThat(existing.digest === hash && existing.data === data);
        return;
      }
      const meta = this.headMeta();
      requireThat(block.height === meta.height + 1 && block.previous === meta.digest);
      requireThat(meta.height < 100_000 && meta.bytes + size <= this.budget);
      // Check current head bytes before extending their committed digest.
      if (meta.height) {
        const old = this.storage.sql.exec('SELECT digest,data FROM blocks WHERE height=?', meta.height).toArray()[0];
        requireThat(old && old.digest === meta.digest);
      }
      this.storage.sql.exec('INSERT INTO blocks VALUES(?,?,?,?)', block.height, hash, data, size);
      this.storage.sql.exec('INSERT INTO chain VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET height=excluded.height,digest=excluded.digest,bytes=excluded.bytes',
        block.height, hash, meta.bytes + size);
    });
    await this.storage.sync(); // Gate the response on confirmed persistence.
    return block;
  }
}
