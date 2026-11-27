-- Apply after supabase-households.sql.

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

create table if not exists public.thalamos_household_codes (
  household_id uuid primary key references public.thalamos_house (household_id) on delete cascade,
  code text not null unique check (code ~ '^[0-9]{6}$'),
  expires_at timestamptz not null
);

create table if not exists public.thalamos_code_attempts (
  user_id uuid primary key references auth.users (id) on delete cascade,
  window_start timestamptz not null,
  attempts integer not null check (attempts between 1 and 6)
);

alter table public.thalamos_household_codes enable row level security;
alter table public.thalamos_code_attempts enable row level security;
revoke all on public.thalamos_household_codes, public.thalamos_code_attempts from public, anon, authenticated;

create or replace function public.thalamos_get_join_code()
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  member_household uuid := public.thalamos_current_household();
  active_code public.thalamos_household_codes%rowtype;
  candidate text;
  issued_at timestamptz;
begin
  if member_household is null then
    raise exception 'House access required' using errcode = '42501';
  end if;

  perform pg_advisory_xact_lock(hashtextextended('thalamos:join-code:' || member_household::text, 0));
  issued_at := clock_timestamp();
  select * into active_code
  from public.thalamos_household_codes
  where household_id = member_household and expires_at > issued_at;
  if found then
    return jsonb_build_object('code', active_code.code, 'expires_at', active_code.expires_at);
  end if;

  delete from public.thalamos_household_codes where expires_at <= issued_at;
  for attempt in 1..12 loop
    -- The first eight hex digits of the UUID are random and contain no version or variant bits.
    candidate := lpad(((('x' || substr(gen_random_uuid()::text, 1, 8))::bit(32)::bigint) % 1000000)::text, 6, '0');
    insert into public.thalamos_household_codes (household_id, code, expires_at)
    values (member_household, candidate, issued_at + interval '30 minutes')
    on conflict (code) do nothing
    returning * into active_code;
    if found then
      return jsonb_build_object('code', active_code.code, 'expires_at', active_code.expires_at);
    end if;
  end loop;

  raise exception 'Could not issue a join code';
end;
$$;

create or replace function public.thalamos_join_by_code(p_code text)
returns text
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
    return 'invalid';
  end if;

  -- Use the same lock as invite redemption and household creation.
  perform pg_advisory_xact_lock(hashtextextended('thalamos:member:' || member_id::text, 0));
  if public.thalamos_current_household() is not null then
    return 'already_member';
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
    return 'rate_limited';
  end if;

  select household_id into target_household
  from public.thalamos_household_codes
  where code = p_code and expires_at > attempt_time;
  if not found then
    return 'invalid';
  end if;

  insert into public.thalamos_members (user_id, household_id) values (member_id, target_household);
  delete from public.thalamos_code_attempts where user_id = member_id;
  return 'joined';
end;
$$;

revoke all on function public.thalamos_get_join_code() from public, anon, authenticated;
revoke all on function public.thalamos_join_by_code(text) from public, anon, authenticated;
grant execute on function public.thalamos_get_join_code() to authenticated;
grant execute on function public.thalamos_join_by_code(text) to authenticated;

commit;
