-- Apply after supabase-multiple-households.sql.
-- Both pickers choose from a household snapshot. Reject a save if that snapshot is stale.

begin;

create or replace function public.thalamos_save_pick(
  p_household_id uuid,
  p_pick_id text,
  p_record jsonb,
  p_expected_revision bigint
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  house public.thalamos_house%rowtype;
begin
  perform public.thalamos_lock_managed_house(p_household_id, false);

  if p_pick_id is null or p_pick_id !~ '^[A-Za-z0-9_-]{1,128}$'
     or jsonb_typeof(p_record) is distinct from 'object'
     or p_record->>'source' is distinct from 'pick' then
    raise exception 'Invalid pick record' using errcode = '22023';
  end if;

  select h.* into strict house
  from public.thalamos_house as h where h.household_id = p_household_id;

  -- A retry of a pick that already saved leaves its result and revision intact.
  if house.logs->p_pick_id = p_record then
    return to_jsonb(house);
  end if;

  if house.revision is distinct from p_expected_revision or house.logs ? p_pick_id then
    raise exception 'Household changed before the pick was saved' using errcode = 'PT409';
  end if;

  return public.thalamos_change(p_household_id, 'logs', p_pick_id, p_record);
end;
$$;

revoke all on function public.thalamos_save_pick(uuid, text, jsonb, bigint) from public, anon, authenticated;
grant execute on function public.thalamos_save_pick(uuid, text, jsonb, bigint) to authenticated;

notify pgrst, 'reload schema';

commit;
