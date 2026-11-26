-- Run in the SQL Editor after the shared database setup in supabase.sql.
-- In Authentication > Hooks, add a Before User Created hook. Choose Postgres
-- and select public.thalamos_invite_signup to require an invitation for sign-up.
-- In Authentication > Sign In / Providers, enable Allow new users to sign up.
-- Turn off Confirm email for this invite-only project to join without an email service.

begin;

create table if not exists public.thalamos_invites (
  token_hash text primary key,
  created_by uuid not null references public.thalamos_members (user_id) on delete cascade,
  expires_at timestamptz not null default (now() + interval '7 days')
);

alter table public.thalamos_invites enable row level security;
revoke all on public.thalamos_invites from public, anon, authenticated, supabase_auth_admin;
grant select on public.thalamos_invites to supabase_auth_admin;

drop policy if exists thalamos_auth_read_invites on public.thalamos_invites;
create policy thalamos_auth_read_invites on public.thalamos_invites
  for select to supabase_auth_admin using (expires_at > now());

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
  if not exists (select 1 from public.thalamos_members where user_id = member_id) then
    raise exception 'House access required' using errcode = '42501';
  end if;

  delete from public.thalamos_invites where expires_at <= now();
  token := replace(gen_random_uuid()::text, '-', '');
  insert into public.thalamos_invites (token_hash, created_by)
  values (encode(sha256(convert_to(token, 'UTF8')), 'hex'), member_id);
  return token;
end;
$$;

create or replace function public.thalamos_redeem_invite(p_token text)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  member_id uuid := auth.uid();
begin
  if member_id is null then
    raise exception 'Sign in required' using errcode = '42501';
  end if;

  -- A member opening a link keeps it available for the person they invite.
  -- Serialize simultaneous requests from the same account before checking membership.
  perform pg_advisory_xact_lock(hashtextextended('thalamos:member:' || member_id::text, 0));
  if exists (select 1 from public.thalamos_members where user_id = member_id) then
    return 'member';
  end if;

  if p_token is null or p_token !~ '^[0-9a-f]{32}$' then
    return 'invalid';
  end if;

  -- Deleting and granting access in one transaction makes the link single-use.
  delete from public.thalamos_invites
  where token_hash = encode(sha256(convert_to(p_token, 'UTF8')), 'hex')
    and expires_at > now();
  if not found then
    return 'invalid';
  end if;

  insert into public.thalamos_members (user_id) values (member_id) on conflict do nothing;
  return 'joined';
end;
$$;

create or replace function public.thalamos_invite_signup(event jsonb)
returns jsonb
language plpgsql
stable
set search_path = ''
as $$
declare
  invite_hash text := event #>> '{user,user_metadata,thalamos_invite_hash}';
begin
  if invite_hash ~ '^[0-9a-f]{64}$' and exists (
    select 1 from public.thalamos_invites where token_hash = invite_hash and expires_at > now()
  ) then
    return '{}'::jsonb;
  end if;

  return '{"error":{"http_code":403,"message":"This invitation is invalid, expired, or already used."}}'::jsonb;
end;
$$;

revoke all on function public.thalamos_create_invite() from public, anon, authenticated;
revoke all on function public.thalamos_redeem_invite(text) from public, anon, authenticated;
grant execute on function public.thalamos_create_invite() to authenticated;
grant execute on function public.thalamos_redeem_invite(text) to authenticated;

revoke all on function public.thalamos_invite_signup(jsonb) from public, anon, authenticated;
grant usage on schema public to supabase_auth_admin;
grant execute on function public.thalamos_invite_signup(jsonb) to supabase_auth_admin;

commit;
