import { drizzle as drizzlePg } from "drizzle-orm/node-postgres";
import { drizzle as drizzleLite } from "drizzle-orm/pglite";
import { PGlite } from "@electric-sql/pglite";
import pg from "pg";
import { migrate, type Db } from "./migrate.ts";

export interface Connection { db: Db; close(): Promise<void> }

/** Postgres when a URL is given (production, docker compose); otherwise an embedded PGlite (tests, quick local runs). */
export async function connect(databaseUrl?: string, opts: { dataDir?: string } = {}): Promise<Connection> {
  let conn: Connection;
  if (databaseUrl) {
    const pool = new pg.Pool({ connectionString: databaseUrl });
    conn = { db: drizzlePg(pool) as unknown as Db, close: () => pool.end() };
  } else {
    const lite = new PGlite(opts.dataDir);
    conn = { db: drizzleLite(lite) as unknown as Db, close: () => lite.close() };
  }
  await migrate(conn.db);
  return conn;
}
