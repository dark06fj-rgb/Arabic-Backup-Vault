-- Remote command bridge for Arabic Backup Vault.
-- Run with the Supabase SQL editor or Supabase CLI migrations.
create extension if not exists pgcrypto;

create table if not exists public.vault_enrollment_codes (
    id uuid primary key default gen_random_uuid(),
    code_hash text not null unique,
    created_at timestamptz not null default now(),
    expires_at timestamptz not null,
    consumed_at timestamptz
);

create table if not exists public.vault_devices (
    id uuid primary key default gen_random_uuid(),
    label text not null,
    device_key_hash text not null,
    created_at timestamptz not null default now(),
    last_seen_at timestamptz,
    disabled_at timestamptz
);

create table if not exists public.vault_commands (
    id uuid primary key default gen_random_uuid(),
    device_id uuid not null references public.vault_devices(id) on delete cascade,
    action text not null check (action in (
        'list_files', 'read_file', 'write_file', 'delete_file',
        'create_backup', 'restore_backup'
    )),
    path text,
    args jsonb not null default '{}'::jsonb,
    status text not null default 'pending' check (status in (
        'pending', 'approved', 'rejected', 'running', 'completed', 'failed', 'expired'
    )),
    requested_at timestamptz not null default now(),
    expires_at timestamptz not null default (now() + interval '30 minutes'),
    approved_at timestamptz,
    completed_at timestamptz,
    result jsonb,
    error_message text
);

create index if not exists vault_commands_device_status_idx
    on public.vault_commands(device_id, status, requested_at);

alter table public.vault_enrollment_codes enable row level security;
alter table public.vault_devices enable row level security;
alter table public.vault_commands enable row level security;

-- Deliberately create no anon/authenticated policies. Only the Edge Function
-- using the service-role key and the owner's trusted Supabase SQL tools may access
-- these tables. Never embed the service-role key in the Android application.

comment on table public.vault_commands is
'Remote requests for the Android vault. Every request starts pending and requires in-app approval.';
comment on column public.vault_commands.args is
'JSON arguments. File bytes, when needed, are base64 in args.content_b64 and must be size-limited by the app.';
comment on column public.vault_devices.device_key_hash is
'SHA-256 hash of a random device secret. The raw secret exists only in Android Keystore.';
