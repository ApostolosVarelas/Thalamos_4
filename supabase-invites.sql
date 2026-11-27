-- Run in the SQL Editor after the shared database setup in supabase.sql.
-- In Authentication > Hooks, add a Before User Created hook. Choose Postgres
-- and select public.thalamos_invite_signup to require an invitation for sign-up.
-- In Authentication > Sign In / Providers, enable Allow new users to sign up.
-- Set the Site URL to the published app in Authentication > URL Configuration.

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

-- Only the Auth hook can bind a pending invitation to a newly created identity.
create table if not exists public.thalamos_invite_signups (
  user_id uuid primary key,
  email text not null,
  token_hash text not null references public.thalamos_invites (token_hash) on delete cascade
);

create index if not exists thalamos_invite_signups_hash on public.thalamos_invite_signups (token_hash);
alter table public.thalamos_invite_signups enable row level security;
revoke all on public.thalamos_invite_signups from public, anon, authenticated, supabase_auth_admin;
grant insert on public.thalamos_invite_signups to supabase_auth_admin;

drop policy if exists thalamos_auth_bind_signup on public.thalamos_invite_signups;
create policy thalamos_auth_bind_signup on public.thalamos_invite_signups
  for insert to supabase_auth_admin with check (true);

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

create or replace function public.thalamos_claim_invite(p_hash text)
returns text
language plpgsql
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

  -- Deleting and granting access in one transaction makes the link single-use.
  delete from public.thalamos_invites
  where token_hash = p_hash and expires_at > now();
  if not found then
    return 'invalid';
  end if;

  insert into public.thalamos_members (user_id) values (member_id) on conflict do nothing;
  return 'joined';
end;
$$;

create or replace function public.thalamos_redeem_invite(p_token text)
returns text
language plpgsql
security definer
set search_path = ''
as $$
begin
  if p_token is null or p_token !~ '^[0-9a-f]{32}$' then
    return 'invalid';
  end if;
  return public.thalamos_claim_invite(encode(sha256(convert_to(p_token, 'UTF8')), 'hex'));
end;
$$;

create or replace function public.thalamos_finish_invite_signup()
returns text
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
    return 'none';
  end if;
  return public.thalamos_claim_invite(invite_hash);
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

revoke all on function public.thalamos_create_invite() from public, anon, authenticated;
revoke all on function public.thalamos_claim_invite(text) from public, anon, authenticated, supabase_auth_admin;
revoke all on function public.thalamos_redeem_invite(text) from public, anon, authenticated;
revoke all on function public.thalamos_finish_invite_signup() from public, anon, authenticated;
grant execute on function public.thalamos_create_invite() to authenticated;
grant execute on function public.thalamos_redeem_invite(text) to authenticated;
grant execute on function public.thalamos_finish_invite_signup() to authenticated;

revoke all on function public.thalamos_invite_signup(jsonb) from public, anon, authenticated;
grant usage on schema public to supabase_auth_admin;
grant execute on function public.thalamos_invite_signup(jsonb) to supabase_auth_admin;

commit;
