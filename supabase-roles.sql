-- Apply after supabase-household-codes.sql.
-- For the original household, set thalamos.legacy_owner_id to the verified member's UUID
-- immediately after BEGIN. Keep that setting out of the repository.

begin;

alter table public.thalamos_members
  add column if not exists role text not null default 'member'
  check (role in ('owner', 'member'));

do $$
declare
  legacy_owner uuid := nullif(current_setting('thalamos.legacy_owner_id', true), '')::uuid;
begin
  if legacy_owner is not null then
    update public.thalamos_members set role = 'owner' where user_id = legacy_owner;
    if not found then
      raise exception 'The specified legacy owner is not a household member';
    end if;
  end if;

  -- A household created through the app originally inserted its creator in the same transaction.
  -- A shared transaction ID is evidence only when it matches a single member.
  with candidates as (
    select member.user_id, member.household_id,
           count(*) over (partition by member.household_id) as candidate_count
    from public.thalamos_members as member
    join public.thalamos_house as house using (household_id)
    where member.xmin = house.xmin
  )
  update public.thalamos_members as member
  set role = 'owner'
  from candidates as candidate
  where member.user_id = candidate.user_id and candidate.candidate_count = 1
    and not exists (
      select 1 from public.thalamos_members as owner
      where owner.household_id = member.household_id and owner.role = 'owner'
    );

  if exists (
    select 1 from public.thalamos_members
    group by household_id
    having count(*) filter (where role = 'owner') = 0
  ) then
    raise exception 'Verify the owner of each existing household before applying the roles migration';
  end if;
end;
$$;

create or replace function public.thalamos_owner_household()
returns uuid
language sql
stable
set search_path = ''
as $$
  select household_id from public.thalamos_members
  where user_id = (select auth.uid()) and role = 'owner';
$$;

revoke all on function public.thalamos_owner_household() from public, anon, authenticated;

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
  insert into public.thalamos_members (user_id, household_id, role)
  values (member_id, house.household_id, 'owner');
  return to_jsonb(house);
end;
$$;

create or replace function public.thalamos_change(p_collection text, p_id text, p_record jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  house public.thalamos_house%rowtype;
  owner_household uuid := public.thalamos_owner_household();
begin
  if owner_household is null then
    raise exception 'Household owner required' using errcode = '42501';
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
  where h.household_id = owner_household
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
  owner_household uuid := public.thalamos_owner_household();
begin
  if owner_household is null then
    raise exception 'Household owner required' using errcode = '42501';
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
  where h.household_id = owner_household
  returning h.* into strict house;

  return to_jsonb(house);
end;
$$;

create or replace function public.thalamos_create_invite()
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  member_id uuid := auth.uid();
  token text;
begin
  if public.thalamos_owner_household() is null then
    raise exception 'Household owner required' using errcode = '42501';
  end if;

  delete from public.thalamos_invites where expires_at <= now();
  token := replace(gen_random_uuid()::text, '-', '');
  insert into public.thalamos_invites (token_hash, created_by)
  values (encode(sha256(convert_to(token, 'UTF8')), 'hex'), member_id);
  return token;
end;
$$;

create or replace function public.thalamos_get_join_code()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  owner_household uuid := public.thalamos_owner_household();
  active_code public.thalamos_household_codes%rowtype;
  candidate text;
  issued_at timestamptz;
begin
  if owner_household is null then
    raise exception 'Household owner required' using errcode = '42501';
  end if;

  perform pg_advisory_xact_lock(hashtextextended('thalamos:join-code:' || owner_household::text, 0));
  issued_at := clock_timestamp();
  select * into active_code
  from public.thalamos_household_codes
  where household_id = owner_household and expires_at > issued_at;
  if found then
    return jsonb_build_object('code', active_code.code, 'expires_at', active_code.expires_at);
  end if;

  delete from public.thalamos_household_codes where expires_at <= issued_at;
  for attempt in 1..12 loop
    -- The first eight hex digits of the UUID are random and contain no version or variant bits.
    candidate := lpad(((('x' || substr(gen_random_uuid()::text, 1, 8))::bit(32)::bigint) % 1000000)::text, 6, '0');
    insert into public.thalamos_household_codes (household_id, code, expires_at)
    values (owner_household, candidate, issued_at + interval '30 minutes')
    on conflict (code) do nothing
    returning * into active_code;
    if found then
      return jsonb_build_object('code', active_code.code, 'expires_at', active_code.expires_at);
    end if;
  end loop;

  raise exception 'Could not issue a join code';
end;
$$;

create or replace function public.thalamos_household_accounts()
returns table (user_id uuid, label text, role text)
language sql
stable
security definer
set search_path = ''
as $$
  select member.user_id,
         coalesce(nullif(case when caller.role = 'owner' or member.user_id = caller.user_id
                              then account.email else split_part(account.email, '@', 1) end, ''), 'Account'),
         member.role
  from public.thalamos_members as caller
  join public.thalamos_members as member using (household_id)
  join auth.users as account on account.id = member.user_id
  where caller.user_id = (select auth.uid())
  order by member.role desc, 2, member.user_id;
$$;

create or replace function public.thalamos_promote_member(p_user_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  owner_household uuid := public.thalamos_owner_household();
begin
  if owner_household is null then
    raise exception 'Household owner required' using errcode = '42501';
  end if;

  -- Repeating a successful promotion has no effect.
  update public.thalamos_members
  set role = 'owner'
  where user_id = p_user_id and household_id = owner_household and role = 'member';

  if not found and not exists (
    select 1 from public.thalamos_members
    where user_id = p_user_id and household_id = owner_household and role = 'owner'
  ) then
    raise exception 'Account is not in this household' using errcode = '22023';
  end if;
end;
$$;

revoke all on function public.thalamos_household_accounts() from public, anon, authenticated;
revoke all on function public.thalamos_promote_member(uuid) from public, anon, authenticated;
grant execute on function public.thalamos_household_accounts() to authenticated;
grant execute on function public.thalamos_promote_member(uuid) to authenticated;

-- The app already watches the household revision for changes.
create or replace function public.thalamos_touch_household_members()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  update public.thalamos_house
  set revision = revision + 1
  where household_id = case when tg_op = 'DELETE' then old.household_id else new.household_id end;
  return null;
end;
$$;

revoke all on function public.thalamos_touch_household_members() from public, anon, authenticated;

drop trigger if exists thalamos_members_changed on public.thalamos_members;
create trigger thalamos_members_changed
after insert or update of role or delete on public.thalamos_members
for each row execute function public.thalamos_touch_household_members();

notify pgrst, 'reload schema';

commit;
