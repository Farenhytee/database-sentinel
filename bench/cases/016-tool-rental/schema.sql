-- Neighbourhood tool-lending marketplace.
create table public.hosts (
  id uuid primary key references auth.users(id),
  display_name text not null,
  neighborhood text,
  payout_share_pct numeric(5,2) not null default 85.00, -- host's cut of each rental
  created_at timestamptz not null default now()
);
alter table public.hosts enable row level security;
create policy "hosts_public_read" on public.hosts for select to anon, authenticated using (true);
-- Meant for display_name/neighborhood edits; row-level only, so payout_share_pct is writable too.
create policy "hosts_update_self" on public.hosts for update to authenticated
  using ((select auth.uid()) = id) with check ((select auth.uid()) = id);

create table public.tools (
  id bigint generated always as identity primary key,
  host_id uuid not null references public.hosts(id),
  name text not null,
  daily_rate_cents integer not null check (daily_rate_cents > 0),
  is_listed boolean not null default true
);
alter table public.tools enable row level security;
-- Public catalog.
create policy "tools_catalog_read" on public.tools for select to anon, authenticated using (true);
create policy "tools_host_insert" on public.tools for insert to authenticated
  with check ((select auth.uid()) = host_id);
create policy "tools_host_update" on public.tools for update to authenticated
  using ((select auth.uid()) = host_id) with check ((select auth.uid()) = host_id);
create policy "tools_host_delete" on public.tools for delete to authenticated
  using ((select auth.uid()) = host_id);

create table public.rentals (
  id bigint generated always as identity primary key,
  tool_id bigint not null references public.tools(id),
  renter_id uuid not null references auth.users(id),
  host_id uuid not null references public.hosts(id),
  days integer not null check (days > 0),
  total_cents integer not null,
  created_at timestamptz not null default now()
);
alter table public.rentals enable row level security;
-- Rentals are created server-side after payment; parties can read their own.
create policy "rentals_parties_read" on public.rentals for select to authenticated
  using ((select auth.uid()) = renter_id or (select auth.uid()) = host_id);

-- Host earnings dashboard. Matviews can't have RLS and inherit default API grants.
create materialized view public.host_earnings as
  select host_id, count(*) as rental_count, sum(total_cents) as gross_cents
  from public.rentals
  group by host_id;

-- seed
insert into public.hosts (id, display_name, neighborhood) values
  ('00000000-0000-0000-0000-000000000001', 'Alice''s Garage', 'Northside'),
  ('00000000-0000-0000-0000-000000000002', 'Bob Builds', 'Riverside');
insert into public.tools (host_id, name, daily_rate_cents) values
  ('00000000-0000-0000-0000-000000000001', 'Cordless drill', 800),
  ('00000000-0000-0000-0000-000000000001', 'Tile saw', 2500),
  ('00000000-0000-0000-0000-000000000002', 'Pressure washer', 3000);
insert into public.rentals (tool_id, renter_id, host_id, days, total_cents) values
  (1, '00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001', 2, 1600),
  (3, '00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002', 1, 3000);
refresh materialized view public.host_earnings;
