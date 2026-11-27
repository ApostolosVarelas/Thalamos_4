-- Apply after supabase-roles.sql.
-- If a household already has multiple owners, provide its verified creator before running:
-- SET LOCAL thalamos.household_creators = '{"household UUID": "creator account UUID"}';

begin;

alter table public.thalamos_house
  add column created_by uuid references auth.users (id) on delete set null;

with owners as (
  select household_id, min(user_id::text)::uuid as user_id
  from public.thalamos_members
  where role = 'owner'
  group by household_id
  having count(*) = 1
)
update public.thalamos_house as house
set created_by = owners.user_id
from owners
where house.household_id = owners.household_id;

update public.thalamos_house as house
set created_by = member.user_id
from public.thalamos_members as member
where member.household_id = house.household_id
  and member.role = 'owner'
  and member.user_id::text = (nullif(current_setting('thalamos.household_creators', true), '')::jsonb ->> house.household_id::text);

do $$
begin
  if exists (
    select 1 from public.thalamos_members as member
    join public.thalamos_house as house using (household_id)
    where house.created_by is null
  ) then
    raise exception 'Verify the creator of each existing household with multiple owners before applying this migration';
  end if;
end;
$$;

alter table public.thalamos_members drop constraint thalamos_members_role_check;
alter table public.thalamos_members add check (role in ('owner', 'admin', 'member'));

update public.thalamos_members as member
set role = 'admin'
from public.thalamos_house as house
where member.household_id = house.household_id
  and member.role = 'owner' and member.user_id <> house.created_by;

alter table public.thalamos_invites add column household_id uuid;
update public.thalamos_invites as invite
set household_id = member.household_id
from public.thalamos_members as member
where member.user_id = invite.created_by;
alter table public.thalamos_invites
  alter column household_id set not null,
  drop constraint thalamos_invites_created_by_fkey;

alter table public.thalamos_members
  drop constraint thalamos_members_pkey,
  drop constraint thalamos_members_household_id_fkey,
  add primary key (household_id, user_id),
  add foreign key (household_id) references public.thalamos_house (household_id) on delete cascade;

create index thalamos_member_by_user on public.thalamos_members (user_id);
create unique index thalamos_single_owner on public.thalamos_members (household_id) where role = 'owner';

alter table public.thalamos_invites
  add foreign key (household_id, created_by)
  references public.thalamos_members (household_id, user_id) on delete cascade;
create index thalamos_invites_by_creator on public.thalamos_invites (household_id, created_by);

drop policy thalamos_read_house on public.thalamos_house;
create policy thalamos_read_house on public.thalamos_house
  for select to authenticated using (
    exists (
      select 1 from public.thalamos_members as member
      where member.household_id = thalamos_house.household_id and member.user_id = (select auth.uid())
    )
  );

-- Older clients cannot choose a household. Disable their unscoped operations.
drop function public.thalamos_change(text, text, jsonb);
drop function public.thalamos_import(jsonb, jsonb);
drop function public.thalamos_create_invite();
drop function public.thalamos_get_join_code();
drop function public.thalamos_household_accounts();
drop function public.thalamos_create_household(text);
drop function public.thalamos_promote_member(uuid);
drop function public.thalamos_join_by_code(text);
drop function public.thalamos_finish_invite_signup();
drop function public.thalamos_redeem_invite(text);
drop function public.thalamos_claim_invite(text);
drop function public.thalamos_owner_household();
drop function public.thalamos_current_household();

-- Lock the household before checking the current role. Removal, promotion and writes
-- share this lock, so a request waiting behind a removal must recheck access.
create function public.thalamos_lock_managed_house(p_household_id uuid, p_owner_only boolean)
returns void
language plpgsql
set search_path = ''
as $$
begin
  perform 1 from public.thalamos_house where household_id = p_household_id for update;
  if not found or not exists (
    select 1 from public.thalamos_members as member
    join public.thalamos_house as house using (household_id)
    where member.household_id = p_household_id and member.user_id = (select auth.uid())
      and ((member.role = 'owner' and house.created_by = member.user_id)
           or (not p_owner_only and member.role = 'admin'))
  ) then
    raise exception 'Household permission required' using errcode = '42501';
  end if;
end;
$$;

create function public.thalamos_create_household(p_household_id uuid, p_name text)
returns uuid
language plpgsql
security definer
set search_path = ''
as $$
declare
  member_id uuid := auth.uid();
  house_name text := btrim(p_name);
begin
  if not exists (select 1 from auth.users where id = member_id and email_confirmed_at is not null) then
    raise exception 'Verified account required' using errcode = '42501';
  end if;
  if p_household_id is null or house_name is null or char_length(house_name) not between 1 and 60 then
    raise exception 'Household name must have 1 to 60 characters' using errcode = '22023';
  end if;

  insert into public.thalamos_house (household_id, name, created_by)
  values (p_household_id, house_name, member_id)
  on conflict (household_id) do nothing;
  if found then
    insert into public.thalamos_members (user_id, household_id, role)
    values (member_id, p_household_id, 'owner');
  elsif not exists (
    select 1 from public.thalamos_house
    where household_id = p_household_id and created_by = member_id and name = house_name
  ) then
    raise exception 'Household could not be created' using errcode = '22023';
  end if;
  return p_household_id;
end;
$$;

create function public.thalamos_change(p_household_id uuid, p_collection text, p_id text, p_record jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  house public.thalamos_house%rowtype;
begin
  perform public.thalamos_lock_managed_house(p_household_id, false);

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
  where h.household_id = p_household_id
  returning h.* into strict house;

  return to_jsonb(house);
end;
$$;

create function public.thalamos_import(p_household_id uuid, p_people jsonb, p_logs jsonb)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  house public.thalamos_house%rowtype;
begin
  perform public.thalamos_lock_managed_house(p_household_id, false);

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
  where h.household_id = p_household_id
  returning h.* into strict house;

  return to_jsonb(house);
end;
$$;

create function public.thalamos_get_join_code(p_household_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  active_code public.thalamos_household_codes%rowtype;
  candidate text;
  issued_at timestamptz;
begin
  perform public.thalamos_lock_managed_house(p_household_id, false);

  issued_at := clock_timestamp();
  select * into active_code
  from public.thalamos_household_codes
  where household_id = p_household_id and expires_at > issued_at;
  if found then
    return jsonb_build_object('code', active_code.code, 'expires_at', active_code.expires_at);
  end if;

  delete from public.thalamos_household_codes where household_id = p_household_id;
  for attempt in 1..12 loop
    -- The first eight hex digits of the UUID are random and contain no version or variant bits.
    candidate := lpad(((('x' || substr(gen_random_uuid()::text, 1, 8))::bit(32)::bigint) % 1000000)::text, 6, '0');
    insert into public.thalamos_household_codes (household_id, code, expires_at)
    values (p_household_id, candidate, issued_at + interval '30 minutes')
    on conflict (code) do nothing
    returning * into active_code;
    if found then
      return jsonb_build_object('code', active_code.code, 'expires_at', active_code.expires_at);
    end if;
  end loop;

  raise exception 'Could not issue a join code';
end;
$$;

create function public.thalamos_create_invite(p_household_id uuid)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  member_id uuid := auth.uid();
  token text;
begin
  perform public.thalamos_lock_managed_house(p_household_id, false);

  delete from public.thalamos_invites where household_id = p_household_id and expires_at <= now();
  token := replace(gen_random_uuid()::text, '-', '');
  insert into public.thalamos_invites (token_hash, created_by, household_id)
  values (encode(sha256(convert_to(token, 'UTF8')), 'hex'), member_id, p_household_id);
  return token;
end;
$$;

create function public.thalamos_join_by_code(p_code text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  member_id uuid := auth.uid();
  target_household uuid;
  guess_count integer;
  attempt_time timestamptz;
begin
  if not exists (select 1 from auth.users where id = member_id and email_confirmed_at is not null) then
    raise exception 'Verified account required' using errcode = '42501';
  end if;
  if p_code is null or p_code !~ '^[0-9]{6}$' then
    return jsonb_build_object('status', 'invalid');
  end if;

  attempt_time := clock_timestamp();
  insert into public.thalamos_code_attempts as counter (user_id, window_start, attempts)
  values (member_id, attempt_time, 1)
  on conflict (user_id) do update
  set window_start = case when counter.window_start <= attempt_time - interval '15 minutes'
                          then attempt_time else counter.window_start end,
      attempts = case when counter.window_start <= attempt_time - interval '15 minutes'
                      then 1 else least(counter.attempts + 1, 6) end
  returning attempts into guess_count;
  if guess_count > 5 then
    return jsonb_build_object('status', 'rate_limited');
  end if;

  select household_id into target_household
  from public.thalamos_household_codes
  where code = p_code and expires_at > attempt_time;
  if not found then
    return jsonb_build_object('status', 'invalid');
  end if;

  perform 1 from public.thalamos_house where household_id = target_household for update;
  if not found or not exists (
    select 1 from public.thalamos_household_codes
    where household_id = target_household and code = p_code and expires_at > clock_timestamp()
  ) then
    return jsonb_build_object('status', 'invalid');
  end if;

  insert into public.thalamos_members (user_id, household_id)
  values (member_id, target_household) on conflict do nothing;
  if not found then
    return jsonb_build_object('status', 'already_member', 'household_id', target_household);
  end if;
  delete from public.thalamos_code_attempts where user_id = member_id;
  return jsonb_build_object('status', 'joined', 'household_id', target_household);
end;
$$;

create function public.thalamos_claim_invite(p_hash text)
returns jsonb
language plpgsql
set search_path = ''
as $$
declare
  member_id uuid := auth.uid();
  target_household uuid;
begin
  if not exists (select 1 from auth.users where id = member_id and email_confirmed_at is not null) then
    raise exception 'Verified account required' using errcode = '42501';
  end if;

  select household_id into target_household
  from public.thalamos_invites where token_hash = p_hash and expires_at > now();

  perform 1 from public.thalamos_house where household_id = target_household for update;
  if not found or not exists (
    select 1 from public.thalamos_invites where token_hash = p_hash and expires_at > clock_timestamp()
  ) then
    return jsonb_build_object('status', 'invalid');
  end if;

  if exists (
    select 1 from public.thalamos_members where household_id = target_household and user_id = member_id
  ) then
    return jsonb_build_object('status', 'already_member', 'household_id', target_household);
  end if;

  delete from public.thalamos_invites where token_hash = p_hash;
  insert into public.thalamos_members (user_id, household_id) values (member_id, target_household);
  return jsonb_build_object('status', 'joined', 'household_id', target_household);
end;
$$;

create function public.thalamos_redeem_invite(p_token text)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
begin
  if p_token is null or p_token !~ '^[0-9a-f]{32}$' then
    return jsonb_build_object('status', 'invalid');
  end if;
  return public.thalamos_claim_invite(encode(sha256(convert_to(p_token, 'UTF8')), 'hex'));
end;
$$;

create function public.thalamos_finish_invite_signup()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  invite_hash text;
begin
  select signup.token_hash into invite_hash
  from public.thalamos_invite_signups as signup
  join auth.users as account on account.id = signup.user_id
  where signup.user_id = auth.uid()
    and lower(account.email) = signup.email
    and account.email_confirmed_at is not null;

  if not found then
    return jsonb_build_object('status', 'none');
  end if;
  return public.thalamos_claim_invite(invite_hash);
end;
$$;

create function public.thalamos_household_accounts(p_household_id uuid)
returns table (user_id uuid, label text, role text)
language sql
stable
security definer
set search_path = ''
as $$
  select member.user_id,
         coalesce(nullif(case when caller.role in ('owner', 'admin') or member.user_id = caller.user_id
                              then account.email else split_part(account.email, '@', 1) end, ''), 'Account'),
         member.role
  from public.thalamos_members as caller
  join public.thalamos_members as member using (household_id)
  join auth.users as account on account.id = member.user_id
  where caller.household_id = p_household_id and caller.user_id = (select auth.uid())
  order by case member.role when 'owner' then 1 when 'admin' then 2 else 3 end, 2, member.user_id;
$$;

create function public.thalamos_make_admin(p_household_id uuid, p_user_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform public.thalamos_lock_managed_house(p_household_id, true);
  update public.thalamos_members set role = 'admin'
  where household_id = p_household_id and user_id = p_user_id and role = 'member';

  if not found and not exists (
    select 1 from public.thalamos_members
    where household_id = p_household_id and user_id = p_user_id and role = 'admin'
  ) then
    raise exception 'This account cannot be made an admin' using errcode = '22023';
  end if;
end;
$$;

create function public.thalamos_remove_member(p_household_id uuid, p_user_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform public.thalamos_lock_managed_house(p_household_id, true);
  if p_user_id = auth.uid() then
    raise exception 'The owner cannot be removed' using errcode = '22023';
  end if;
  delete from public.thalamos_members
  where household_id = p_household_id and user_id = p_user_id and role in ('member', 'admin');
end;
$$;

create function public.thalamos_delete_household(p_household_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform public.thalamos_lock_managed_house(p_household_id, true);
  delete from public.thalamos_house where household_id = p_household_id;
end;
$$;

revoke all on function public.thalamos_lock_managed_house(uuid, boolean), public.thalamos_claim_invite(text)
  from public, anon, authenticated;

revoke all on function
  public.thalamos_create_household(uuid, text), public.thalamos_change(uuid, text, text, jsonb),
  public.thalamos_import(uuid, jsonb, jsonb), public.thalamos_create_invite(uuid), public.thalamos_get_join_code(uuid),
  public.thalamos_join_by_code(text), public.thalamos_redeem_invite(text), public.thalamos_finish_invite_signup(),
  public.thalamos_household_accounts(uuid), public.thalamos_make_admin(uuid, uuid),
  public.thalamos_remove_member(uuid, uuid), public.thalamos_delete_household(uuid)
from public, anon, authenticated;

grant execute on function
  public.thalamos_create_household(uuid, text), public.thalamos_change(uuid, text, text, jsonb),
  public.thalamos_import(uuid, jsonb, jsonb), public.thalamos_create_invite(uuid), public.thalamos_get_join_code(uuid),
  public.thalamos_join_by_code(text), public.thalamos_redeem_invite(text), public.thalamos_finish_invite_signup(),
  public.thalamos_household_accounts(uuid), public.thalamos_make_admin(uuid, uuid),
  public.thalamos_remove_member(uuid, uuid), public.thalamos_delete_household(uuid)
to authenticated;

notify pgrst, 'reload schema';

commit;
