-- For a fresh project run this, then supabase-invites.sql, then supabase-households.sql.
-- In Authentication > Users, create an email/password user for each housemate.
-- Confirm those accounts and grant access using the example at the end of this file.
-- Set SUPABASE_URL and SUPABASE_PUBLISHABLE_KEY in index.html before publishing.

begin;

do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'thalamos_house' and column_name = 'household_id'
  ) then
    raise exception 'This project already supports multiple households. Use supabase-households.sql.';
  end if;
end;
$$;

create table if not exists public.thalamos_members (
  user_id uuid primary key references auth.users (id) on delete cascade
);

create table if not exists public.thalamos_house (
  id boolean primary key default true check (id),
  revision bigint not null default 0,
  people jsonb not null default '{}'::jsonb check (jsonb_typeof(people) = 'object'),
  logs jsonb not null default '{}'::jsonb check (jsonb_typeof(logs) = 'object')
);

insert into public.thalamos_house (id) values (true) on conflict do nothing;

alter table public.thalamos_members enable row level security;
alter table public.thalamos_house enable row level security;
revoke all on public.thalamos_members, public.thalamos_house from public, anon, authenticated;
grant select on public.thalamos_members, public.thalamos_house to authenticated;

drop policy if exists thalamos_own_membership on public.thalamos_members;
create policy thalamos_own_membership on public.thalamos_members
  for select to authenticated using (user_id = (select auth.uid()));

drop policy if exists thalamos_read_house on public.thalamos_house;
create policy thalamos_read_house on public.thalamos_house
  for select to authenticated using (
    exists (select 1 from public.thalamos_members where user_id = (select auth.uid()))
  );

-- Each write updates one record. Postgres serializes concurrent updates to this row.
create or replace function public.thalamos_change(p_collection text, p_id text, p_record jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  house public.thalamos_house%rowtype;
begin
  if not exists (select 1 from public.thalamos_members where user_id = auth.uid()) then
    raise exception 'House access required' using errcode = '42501';
  end if;

  if p_collection is null or p_collection not in ('people', 'logs')
     or p_id is null or p_id !~ '^[A-Za-z0-9_-]{1,128}$'
     or jsonb_typeof(p_record) not in ('object', 'null') then
    raise exception 'Invalid house record' using errcode = '22023';
  end if;

  if p_record = 'null'::jsonb then
    p_record := null;
  end if;

  update public.thalamos_house as h
  set people = case
        when p_collection <> 'people' then h.people
        when p_record is null then h.people - p_id
        else jsonb_set(h.people, array[p_id], p_record)
      end,
      logs = case
        when p_collection <> 'logs' then h.logs
        when p_record is null then h.logs - p_id
        else jsonb_set(h.logs, array[p_id], p_record)
      end,
      revision = h.revision + 1
  where h.id
  returning h.* into strict house;

  return to_jsonb(house);
end;
$$;

create or replace function public.thalamos_import(p_people jsonb, p_logs jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  house public.thalamos_house%rowtype;
begin
  if not exists (select 1 from public.thalamos_members where user_id = auth.uid()) then
    raise exception 'House access required' using errcode = '42501';
  end if;

  if jsonb_typeof(p_people) is distinct from 'object' or jsonb_typeof(p_logs) is distinct from 'object' then
    raise exception 'Invalid house backup' using errcode = '22023';
  end if;

  if exists (select 1 from jsonb_each(p_people) where key !~ '^[A-Za-z0-9_-]{1,128}$' or jsonb_typeof(value) <> 'object')
     or exists (select 1 from jsonb_each(p_logs) where key !~ '^[A-Za-z0-9_-]{1,128}$' or jsonb_typeof(value) <> 'object') then
    raise exception 'Invalid backup record' using errcode = '22023';
  end if;

  -- The right side wins on duplicate IDs, including records added during import.
  update public.thalamos_house as h
  set people = p_people || h.people,
      logs = p_logs || h.logs,
      revision = h.revision + 1
  where h.id
  returning h.* into strict house;

  return to_jsonb(house);
end;
$$;

revoke all on function public.thalamos_change(text, text, jsonb) from public, anon, authenticated;
revoke all on function public.thalamos_import(jsonb, jsonb) from public, anon, authenticated;
grant execute on function public.thalamos_change(text, text, jsonb) to authenticated;
grant execute on function public.thalamos_import(jsonb, jsonb) to authenticated;

do $$
begin
  if not exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    create publication supabase_realtime;
  end if;
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'thalamos_house'
  ) then
    alter publication supabase_realtime add table public.thalamos_house;
  end if;
end;
$$;

commit;

-- After creating the Supabase Auth users, replace the email addresses and run this separately.
-- insert into public.thalamos_members (user_id)
-- select id from auth.users where lower(email) in ('housemate@example.com')
-- on conflict do nothing;

-- For a portable backup when the website is unavailable, run this in the SQL Editor
-- and save the JSON value as a .json file. Import it from the Log tab after redeploying.
-- select jsonb_build_object('version', 1, 'people', people, 'logs', logs) as backup
-- from public.thalamos_house where id;
