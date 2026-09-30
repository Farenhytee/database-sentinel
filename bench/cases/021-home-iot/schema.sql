-- Smart-home hub: shared homes, devices, automation rules, raw telemetry.
create schema if not exists private;
grant usage on schema private to authenticated;

create table public.homes (
  id uuid primary key default gen_random_uuid(),
  name text not null
);

create table public.home_members (
  home_id uuid not null references public.homes(id),
  user_id uuid not null references auth.users(id),
  primary key (home_id, user_id)
);

create table public.devices (
  id bigint generated always as identity primary key,
  home_id uuid not null references public.homes(id),
  label text not null,
  kind text not null check (kind in ('lock', 'camera', 'thermostat', 'light'))
);

create table public.automation_rules (
  id bigint generated always as identity primary key,
  home_id uuid not null references public.homes(id),
  device_id bigint not null references public.devices(id),
  trigger_expr text not null,
  action text not null,
  enabled boolean not null default true
);

-- Ingested by the device gateway (service role).
create table public.telemetry_raw (
  id bigint generated always as identity primary key,
  device_id bigint not null references public.devices(id),
  reading jsonb not null,
  recorded_at timestamptz not null default now()
);

create function private.is_home_member(h uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.home_members m
    where m.home_id = h and m.user_id = (select auth.uid())
  )
$$;

alter table public.homes enable row level security;
alter table public.home_members enable row level security;
alter table public.devices enable row level security;
alter table public.telemetry_raw enable row level security;

create policy "homes_member_read" on public.homes for select to authenticated
  using (private.is_home_member(id));
create policy "home_members_read" on public.home_members for select to authenticated
  using (private.is_home_member(home_id));
create policy "devices_member_all" on public.devices for all to authenticated
  using (private.is_home_member(home_id)) with check (private.is_home_member(home_id));
create policy "automation_rules_member_all" on public.automation_rules for all to authenticated
  using (private.is_home_member(home_id)) with check (private.is_home_member(home_id));

-- seed
insert into public.homes (id, name) values
  ('20000000-0000-0000-0000-000000000001', 'Alice flat'),
  ('20000000-0000-0000-0000-000000000002', 'Bob house');
insert into public.home_members (home_id, user_id) values
  ('20000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001'),
  ('20000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000002');
insert into public.devices (home_id, label, kind) values
  ('20000000-0000-0000-0000-000000000001', 'Front door', 'lock'),
  ('20000000-0000-0000-0000-000000000002', 'Garage cam', 'camera');
insert into public.automation_rules (home_id, device_id, trigger_expr, action) values
  ('20000000-0000-0000-0000-000000000001', 1, 'presence.away', 'lock'),
  ('20000000-0000-0000-0000-000000000002', 2, 'time.after(22:00)', 'record');
insert into public.telemetry_raw (device_id, reading) values
  (1, '{"state": "unlocked", "battery": 81}'),
  (2, '{"motion": true}');
