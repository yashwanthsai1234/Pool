// A small IndexedDB wrapper. Each write is one readwrite transaction, so a failed write (for example a quota
// error) aborts as a whole and leaves no half-written entry. CryptoKey objects are stored by structured clone;
// a non-extractable key stays non-extractable after a reload.
// Source: https://w3c.github.io/IndexedDB/#transaction-concept (atomic commit or abort)
// Source: https://w3c.github.io/webcrypto/#cryptokey-interface-clone (CryptoKey is serializable)
import { VaultError } from './errors.ts';

type StoreName = 'entries' | 'enrollment';
type Row = { id: string; role: string };

const done = <T>(req: IDBRequest<T>): Promise<T> =>
  new Promise((resolve, reject) => {
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });

export class Store {
  readonly #db: Promise<IDBDatabase>;

  constructor(dbName: string) {
    const req = indexedDB.open(dbName, 1);
    req.onupgradeneeded = () => {
      for (const name of ['entries', 'enrollment'] as const) {
        req.result.createObjectStore(name, { keyPath: 'id' }).createIndex('role', 'role');
      }
    };
    this.#db = done(req);
  }

  async get<T extends Row>(store: StoreName, id: string): Promise<T | undefined> {
    const db = await this.#db;
    return done(db.transaction(store).objectStore(store).get(id));
  }

  /** Every row of one role: a role never sees another role's rows (P4.2-04). */
  async byRole<T extends Row>(store: StoreName, role: string): Promise<T[]> {
    const db = await this.#db;
    return done(db.transaction(store).objectStore(store).index('role').getAll(role));
  }

  /** Writes one row atomically; any failure becomes `STORAGE_FAILED` with nothing stored. */
  async put<T extends Row>(store: StoreName, row: T): Promise<void> {
    const db = await this.#db;
    try {
      const tx = db.transaction(store, 'readwrite');
      tx.objectStore(store).put(row);
      await new Promise<void>((resolve, reject) => {
        tx.oncomplete = () => resolve();
        tx.onabort = () => reject(tx.error);
        tx.onerror = () => reject(tx.error);
      });
    } catch {
      throw new VaultError('STORAGE_FAILED');
    }
  }

  async close(): Promise<void> {
    (await this.#db).close();
  }
}
