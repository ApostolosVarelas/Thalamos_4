-- Apply after supabase.sql and supabase-invites.sql.
-- This upgrades the original household in place and gives new accounts private households.

begin;

do $$
begin
  if exists (
    select 1 from information_schema.columns
    where table_schema = 'public' and table_name = 'thalamos_members' and column_name = 'role'
  ) then
    raise exception 'This project already supports household roles. Use supabase-roles.sql.';
  end if;
end;
$$;

alter table public.thalamos_house
  add column if not exists household_id uuid not null default gen_random_uuid(),
  add column if not exists name text not null default 'Thalamos 4';

do $$
begin
  if exists (
    select 1 from pg_constraint
    where conrelid = 'public.thalamos_house'::regclass
      and conname = 'thalamos_house_pkey'
      and pg_get_constraintdef(oid) = 'PRIMARY KEY (id)'
  ) then
    alter table public.thalamos_house
      drop constraint thalamos_house_pkey,
      add constraint thalamos_house_pkey primary key (household_id);
  end if;
end;
$$;

-- Keep the original boolean column for clients already open during the upgrade.
alter table public.thalamos_members
  add column if not exists household_id uuid references public.thalamos_house (household_id);

-- The old schema has exactly one household. On a repeat run every member already has a household.
update public.thalamos_members
set household_id = (select household_id from public.thalamos_house limit 1)
where household_id is null;
alter table public.thalamos_members alter column household_id set not null;

drop policy if exists thalamos_read_house on public.thalamos_house;
create policy thalamos_read_house on public.thalamos_house
  for select to authenticated using (
    household_id = (select member.household_id from public.thalamos_members as member
                    where member.user_id = (select auth.uid()))
  );

create or replace function public.thalamos_create_household(p_name text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  member_id uuid := auth.uid();
  house public.thalamos_house%rowtype;
  house_name text := btrim(p_name);
begin
  if not exists (select 1 from auth.users where id = member_id and email_confirmed_at is not null) then
    raise exception 'Verified account required' using errcode = '42501';
  end if;
  if house_name is null or char_length(house_name) not between 1 and 60 then
    raise exception 'Household name must have 1 to 60 characters' using errcode = '22023';
  end if;

  -- Joining and creating share the same per-account lock.
  perform pg_advisory_xact_lock(hashtextextended('thalamos:member:' || member_id::text, 0));
  select h.* into house
  from public.thalamos_house as h
  join public.thalamos_members as member using (household_id)
  where member.user_id = member_id;
  if found then
    return to_jsonb(house);
  end if;

  insert into public.thalamos_house (name) values (house_name) returning * into house;
  insert into public.thalamos_members (user_id, household_id) values (member_id, house.household_id);
  return to_jsonb(house);
end;
$$;

create or replace function public.thalamos_current_household()
returns uuid
language sql
stable
set search_path = ''
as $$
  select household_id from public.thalamos_members where user_id = (select auth.uid());
$$;

create or replace function public.thalamos_change(p_collection text, p_id text, p_record jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  house public.thalamos_house%rowtype;
  member_household uuid := public.thalamos_current_household();
begin
  if member_household is null then
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
  where h.household_id = member_household
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
  member_household uuid := public.thalamos_current_household();
begin
  if member_household is null then
    raise exception 'House access required' using errcode = '42501';
  end if;

  if jsonb_typeof(p_people) is distinct from 'object' or jsonb_typeof(p_logs) is distinct from 'object' then
    raise exception 'Invalid house backup' using errcode = '22023';
  end if;

  if exists (select 1 from jsonb_each(p_people) where key !~ '^[A-Za-z0-9_-]{1,128}$' or jsonb_typeof(value) <> 'object')
     or exists (select 1 from jsonb_each(p_logs) where key !~ '^[A-Za-z0-9_-]{1,128}$' or jsonb_typeof(value) <> 'object') then
    raise exception 'Invalid backup record' using errcode = '22023';
  end if;

  update public.thalamos_house as h
  set people = p_people || h.people,
      logs = p_logs || h.logs,
      revision = h.revision + 1
  where h.household_id = member_household
  returning h.* into strict house;

  return to_jsonb(house);
end;
$$;

create or replace function public.thalamos_claim_invite(p_hash text)
returns text
language plpgsql
set search_path = ''
as $$
declare
  member_id uuid := auth.uid();
  member_household uuid;
  invite_household uuid;
begin
  if not exists (select 1 from auth.users where id = member_id and email_confirmed_at is not null) then
    raise exception 'Verified account required' using errcode = '42501';
  end if;

  perform pg_advisory_xact_lock(hashtextextended('thalamos:member:' || member_id::text, 0));
  member_household := public.thalamos_current_household();
  select inviter.household_id into invite_household
  from public.thalamos_invites as invite
  join public.thalamos_members as inviter on inviter.user_id = invite.created_by
  where invite.token_hash = p_hash and invite.expires_at > now();

  if member_household is not null then
    if invite_household is not null and invite_household <> member_household then
      return 'already_member';
    end if;
    return 'member';
  end if;
  if invite_household is null then
    return 'invalid';
  end if;

  -- Consume the invite and add the new member in the same transaction.
  delete from public.thalamos_invites where token_hash = p_hash and expires_at > now();
  if not found then
    return 'invalid';
  end if;

  insert into public.thalamos_members (user_id, household_id) values (member_id, invite_household);
  return 'joined';
end;
$$;

create or replace function public.thalamos_invite_signup(event jsonb)
returns jsonb
language plpgsql
set search_path = ''
as $$
declare
  invite_hash text := event #>> '{user,user_metadata,thalamos_invite_hash}';
  signup_id uuid := (event #>> '{user,id}')::uuid;
  signup_email text := lower(event #>> '{user,email}');
begin
  -- An account without an invite starts without access to any household.
  if invite_hash is null then
    return '{}'::jsonb;
  end if;

  if signup_id is not null and length(signup_email) > 0 and invite_hash ~ '^[0-9a-f]{64}$' then
    insert into public.thalamos_invite_signups (user_id, email, token_hash)
    select signup_id, signup_email, token_hash
    from public.thalamos_invites
    where token_hash = invite_hash and expires_at > now()
    on conflict do nothing;
    if found then
      return '{}'::jsonb;
    end if;
  end if;

  return '{"error":{"http_code":403,"message":"This invitation is invalid, expired, or already used."}}'::jsonb;
end;
$$;

revoke all on function public.thalamos_current_household() from public, anon, authenticated;
revoke all on function public.thalamos_create_household(text) from public, anon, authenticated;
grant execute on function public.thalamos_create_household(text) to authenticated;

commit;
