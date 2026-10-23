-- CentralScan v1 — Supabase schema. Run once in the Supabase SQL editor.
-- Both tables use RLS with a public read policy so the deployed frontend can
-- read history without a user table; writes happen only with the service key.

create table if not exists scans (
  scan_id      text primary key,
  target       text not null,
  scan_type    text not null default 'url',
  status       text not null default 'queued',
  progress     text,
  created_at   timestamptz,
  completed_at timestamptz,
  error        text,
  simulated    boolean default false
);

create table if not exists findings (
  id            uuid primary key default gen_random_uuid(),
  scan_id       text not null references scans(scan_id) on delete cascade,
  severity      text not null,
  priority      int default 0,
  title         text not null,
  explanation   text,
  impact        text,
  suggested_fix text,
  location      text,
  evidence      text,
  source_scanner text,
  cve           text,
  cvss          double precision,
  owasp         text,
  references_   jsonb,
  created_at    timestamptz default now()
);

create index if not exists findings_scan_idx on findings(scan_id);
create index if not exists scans_created_idx on scans(created_at desc);

alter table scans enable row level security;
alter table findings enable row level security;

drop policy if exists "public read scans" on scans;
create policy "public read scans" on scans for select using (true);

drop policy if exists "public read findings" on findings;
create policy "public read findings" on findings for select using (true);

-- Writes use the service-role key (bypasses RLS); no write policies for anon.
