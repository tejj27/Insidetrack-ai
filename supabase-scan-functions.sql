-- ============================================================
-- InsideTrack scan limit — Supabase SQL functions
-- Run this ONCE in: Supabase Dashboard → SQL Editor → New Query
-- ============================================================

-- 1. Atomic check + increment
--    Returns { allowed, scans_used, plan }
--    Uses UPDATE ... WHERE scans_used < limit, so it's race-safe.
--    SECURITY DEFINER means it runs with the function owner's rights
--    (bypasses RLS) — safe because it's only callable via the service key.
create or replace function increment_scan_if_under_limit(p_user_id uuid, p_limit int)
returns json
language plpgsql
security definer
as $$
declare
  v_scans int;
  v_plan  text;
begin
  -- Atomic: only updates if scans_used < limit (or plan = 'pro')
  update profiles
  set scans_used = scans_used + 1
  where id = p_user_id
    and (plan = 'pro' or scans_used < p_limit)
  returning scans_used, plan
  into v_scans, v_plan;

  if found then
    return json_build_object(
      'allowed',    true,
      'scans_used', v_scans,
      'plan',       coalesce(v_plan, 'free')
    );
  else
    -- Update didn't happen — read current state to return in response
    select scans_used, plan
    into v_scans, v_plan
    from profiles
    where id = p_user_id;

    return json_build_object(
      'allowed',    false,
      'scans_used', coalesce(v_scans, 0),
      'plan',       coalesce(v_plan, 'free')
    );
  end if;
end;
$$;

-- 2. Guest scan migration
--    Called once on sign-in/sign-up to carry over any scans done as a guest.
--    Uses GREATEST() so it never lowers the count if the user already has more.
create or replace function migrate_guest_scans(p_user_id uuid, p_guest_count int)
returns void
language plpgsql
security definer
as $$
begin
  update profiles
  set scans_used = greatest(scans_used, p_guest_count)
  where id = p_user_id;
end;
$$;
