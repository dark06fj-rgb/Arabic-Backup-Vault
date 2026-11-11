-- Make enrollment-code consumption and device creation atomic.
create or replace function public.enroll_vault_device(
    p_code_hash text,
    p_device_key_hash text,
    p_label text
) returns uuid
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_code_id uuid;
    v_device_id uuid;
begin
    update public.vault_enrollment_codes
       set consumed_at = now()
     where code_hash = p_code_hash
       and consumed_at is null
       and expires_at > now()
     returning id into v_code_id;

    if v_code_id is null then
        raise exception 'pairing_code_invalid_or_expired';
    end if;

    insert into public.vault_devices(label, device_key_hash)
    values (left(coalesce(nullif(p_label, ''), 'Android vault'), 80), p_device_key_hash)
    returning id into v_device_id;

    return v_device_id;
end;
$$;

revoke all on function public.enroll_vault_device(text, text, text) from public, anon, authenticated;
grant execute on function public.enroll_vault_device(text, text, text) to service_role;
