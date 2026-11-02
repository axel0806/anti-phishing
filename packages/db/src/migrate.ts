import { sql } from "drizzle-orm";
import type { PgDatabase, PgQueryResultHKT } from "drizzle-orm/pg-core";

export type Db = PgDatabase<PgQueryResultHKT>;

/** Ordered, append-only migrations. Never edit an applied entry; add a new one. */
export const MIGRATIONS: { id: string; sql: string }[] = [
  {
    id: "0001_init",
    sql: `
create table orgs (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  policy jsonb not null default '{}',
  locked_fields text[] not null default '{}'
);
create table users (
  id uuid primary key default gen_random_uuid(),
  org_id uuid references orgs(id),
  email text not null unique,
  provider text not null default 'gmail',
  role text not null default 'user' check (role in ('user','viewer','analyst','admin')),
  encrypted_tokens text,
  settings_overrides jsonb not null default '{}'
);
create table list_entries (
  id uuid primary key default gen_random_uuid(),
  owner_kind text not null check (owner_kind in ('user','org')),
  owner_id uuid not null,
  kind text not null check (kind in ('allow','block')),
  match_type text not null check (match_type in ('address','domain')),
  value text not null,
  created_by uuid,
  constraint list_entries_unique unique (owner_id, kind, match_type, value)
);
create index list_entries_owner_kind_value on list_entries (owner_id, kind, value);
create table sender_history (
  user_id uuid not null references users(id) on delete cascade,
  sender_address text not null,
  first_seen timestamptz not null default now(),
  messages_received int not null default 1,
  user_replied boolean not null default false,
  primary key (user_id, sender_address)
);
create table scans (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references users(id) on delete cascade,
  provider_message_id text not null,
  score int not null check (score between 0 and 100),
  verdict text not null check (verdict in ('safe','suspicious','phishing')),
  ai_used boolean not null default false,
  latency_ms int not null,
  settings_version int not null,
  reason text,
  sender text,
  subject_hash text,
  pinned boolean not null default false,
  created_at timestamptz not null default now(),
  constraint scans_user_message unique (user_id, provider_message_id)
);
create index scans_user_created on scans (user_id, created_at desc);
create index scans_verdict_created on scans (verdict, created_at desc);
create table scan_flags (
  scan_id uuid not null references scans(id) on delete cascade,
  flag_id text not null,
  weight_applied int not null,
  evidence text not null,
  primary key (scan_id, flag_id)
);
create index scan_flags_flag on scan_flags (flag_id);
create table feedback (
  scan_id uuid not null references scans(id) on delete cascade,
  user_id uuid not null references users(id) on delete cascade,
  label text not null check (label in ('not_phishing','phishing')),
  created_at timestamptz not null default now(),
  primary key (scan_id, user_id)
);`,
  },
];

/** Applies pending migrations inside a transaction each; safe to call on every start. */
export async function migrate(db: Db): Promise<string[]> {
  await db.execute(sql`create table if not exists schema_migrations (id text primary key, applied_at timestamptz not null default now())`);
  const done = new Set((await db.execute(sql`select id from schema_migrations`)).rows.map((r) => (r as { id: string }).id));
  const applied: string[] = [];
  for (const m of MIGRATIONS) {
    if (done.has(m.id)) continue;
    await db.transaction(async (tx) => {
      // One statement per call: prepared queries cannot hold several. Migrations must not contain ';' inside literals.
      for (const stmt of m.sql.split(";").map((s) => s.trim()).filter(Boolean)) await tx.execute(sql.raw(stmt));
      await tx.execute(sql`insert into schema_migrations (id) values (${m.id})`);
    });
    applied.push(m.id);
  }
  return applied;
}
