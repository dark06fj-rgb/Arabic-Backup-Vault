-- Generate a short-lived, single-use pairing code without storing its plaintext.
create or replace function public.create_vault_enrollment_code()
returns text
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    v_code text;
begin
    v_code := encode(gen_random_bytes(24), 'hex');
    insert into public.vault_enrollment_codes(code_hash, expires_at)
    values (encode(digest(v_code, 'sha256'), 'hex'), now() + interval '15 minutes');
    return v_code;
end;
$$;

revoke all on function public.create_vault_enrollment_code() from public, anon, authenticated;
