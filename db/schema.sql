-- =====================================================================
-- file: db/schema.sql
-- Hardening: valid RLS policy syntax, UTC-safe logic, safer SECURITY DEFINER
-- =====================================================================

-- EXTENSIONS -----------------------------------------------------------
create extension if not exists "uuid-ossp";

-- TABLES ---------------------------------------------------------------

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  created_at timestamptz not null default now()
);

create table if not exists public.meditation_logs (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  started_at timestamptz not null default now(),
  duration_seconds int not null check (duration_seconds > 0)
);

create table if not exists public.journals (
  id uuid primary key default uuid_generate_v4(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  entry_date date not null default (now() at time zone 'utc')::date,
  reflection_text text,
  created_at timestamptz not null default now(),
  unique (user_id, entry_date)
);

-- INDEXES (why: perf for common filters & streak calc) -----------------
create index if not exists idx_meditation_logs_user_started
  on public.meditation_logs (user_id, started_at);
create index if not exists idx_journals_user_entry_date
  on public.journals (user_id, entry_date);

-- RLS ------------------------------------------------------------------
alter table public.profiles enable row level security;
alter table public.meditation_logs enable row level security;
alter table public.journals enable row level security;

-- POLICIES (Postgres: one FOR per policy) ------------------------------

-- profiles
drop policy if exists "select own profile" on public.profiles;
create policy "select own profile"
  on public.profiles
  for select
  using (auth.uid() = id);

drop policy if exists "update own profile" on public.profiles;
create policy "update own profile"
  on public.profiles
  for update
  using (auth.uid() = id);

drop policy if exists "insert own profile" on public.profiles;
create policy "insert own profile"
  on public.profiles
  for insert
  with check (auth.uid() = id);

-- meditation_logs
drop policy if exists "select own meditation logs" on public.meditation_logs;
create policy "select own meditation logs"
  on public.meditation_logs
  for select
  using (auth.uid() = user_id);

drop policy if exists "insert own meditation logs" on public.meditation_logs;
create policy "insert own meditation logs"
  on public.meditation_logs
  for insert
  with check (auth.uid() = user_id);

drop policy if exists "update own meditation logs" on public.meditation_logs;
create policy "update own meditation logs"
  on public.meditation_logs
  for update
  using (auth.uid() = user_id);

drop policy if exists "delete own meditation logs" on public.meditation_logs;
create policy "delete own meditation logs"
  on public.meditation_logs
  for delete
  using (auth.uid() = user_id);

-- journals
drop policy if exists "select own journals" on public.journals;
create policy "select own journals"
  on public.journals
  for select
  using (auth.uid() = user_id);

drop policy if exists "insert own journals" on public.journals;
create policy "insert own journals"
  on public.journals
  for insert
  with check (auth.uid() = user_id);

drop policy if exists "update own journals" on public.journals;
create policy "update own journals"
  on public.journals
  for update
  using (auth.uid() = user_id);

drop policy if exists "delete own journals" on public.journals;
create policy "delete own journals"
  on public.journals
  for delete
  using (auth.uid() = user_id);

-- FUNCTION: current & longest streak (UTC day buckets) -----------------
create or replace function public.get_streaks(p_user uuid)
returns table(current_streak int, longest_streak int)
language sql
stable
as $$
with days as (
  select distinct ((started_at at time zone 'utc')::date) as d
  from public.meditation_logs
  where user_id = p_user
),
streak_runs as (
  select d, d - (row_number() over(order by d))::int as grp
  from days
),
grouped as (
  select grp, min(d) as start_d, max(d) as end_d, count(*) as len
  from streak_runs
  group by grp
)
select
  coalesce((
    select len from grouped
    where end_d = (now() at time zone 'utc')::date
  ), 0) as current_streak,
  coalesce((select max(len) from grouped), 0) as longest_streak;
$$;

-- TRIGGER: auto-create profile on signup -------------------------------
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  -- why: ensure profile row even if client forgets to create it
  insert into public.profiles (id, display_name)
  values (new.id, new.raw_user_meta_data->>'name')
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_user();

-- MATERIALIZED VIEW: global daily pulse (UTC) --------------------------
drop materialized view if exists public.daily_pulse;

create materialized view public.daily_pulse as
with today_utc as (
  select (now() at time zone 'utc')::date as d
)
select t.d as pulse_date,
       count(distinct ml.user_id) as meditators_today
from today_utc t
left join public.meditation_logs ml
  on ((ml.started_at at time zone 'utc')::date) = t.d
group by t.d;

-- Unique index enables CONCURRENT refresh if desired
create unique index if not exists daily_pulse_pkey on public.daily_pulse (pulse_date);

-- VIEW REFRESH helper (security definer for app role) ------------------
create or replace function public.refresh_daily_pulse()
returns void
language sql
security definer
set search_path = public
as $$
  refresh materialized view public.daily_pulse;
$$;

-- PRIVILEGES (why: RLS needs privileges granted to be usable) ----------
-- Adjust to your security posture; commonly only `authenticated` gets DML.
grant usage on schema public to anon, authenticated, service_role;

grant select, insert, update on table public.profiles to authenticated;
grant select, insert, update, delete on table public.meditation_logs to authenticated;
grant select, insert, update, delete on table public.journals to authenticated;

-- Allow reading the pulse publicly if you want to show a public widget
grant select on materialized view public.daily_pulse to anon, authenticated;

-- Allow app to refresh the MV (or restrict to service_role only)
grant execute on function public.refresh_daily_pulse() to authenticated, service_role;

-- (Optional) if you plan to REFRESH CONCURRENTLY:
--   refresh materialized view concurrently public.daily_pulse;
-- requires the unique index created above.
