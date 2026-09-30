-- Internal inspections app: most tables have RLS off but API grants revoked (backend-only via service role).
-- Modeled on a real project pattern: RLS off is only exploitable where anon/authenticated keep grants.
create table public.regions (id bigint generated always as identity primary key, name text not null);
create table public.inspectors (
  id bigint generated always as identity primary key,
  region_id bigint references public.regions(id),
  full_name text not null,
  email text not null
);
create table public.sites (id bigint generated always as identity primary key, region_id bigint references public.regions(id), address text);
create table public.inspection_notes (
  id bigint generated always as identity primary key,
  site_id bigint references public.sites(id),
  inspector_id bigint references public.inspectors(id),
  note text
);
revoke all on public.regions, public.inspectors, public.sites, public.inspection_notes from anon, authenticated;

-- Reporting view over revoked tables, itself revoked: not reachable via the API.
create view public.v_site_notes as
  select s.id as site_id, s.address, count(n.id) as notes from public.sites s left join public.inspection_notes n on n.site_id = s.id group by s.id, s.address;
revoke all on public.v_site_notes from anon, authenticated;

-- Public feedback form table: RLS off and default grants kept. Anyone can read and edit all feedback.
create table public.site_feedback (
  id bigint generated always as identity primary key,
  site_id bigint,
  reporter_email text,
  message text
);

-- Invoker rights over revoked tables: an anon /rpc call fails with permission denied. Not exploitable.
create function public.purge_inspector(p_id bigint) returns void
language sql set search_path = '' as $$ delete from public.inspection_notes where inspector_id = p_id; delete from public.inspectors where id = p_id $$;

-- Definer rights: runs as owner, so anon can wipe feedback and sites via /rpc/reset_feedback.
create function public.reset_feedback() returns void
language sql security definer set search_path = '' as $$ delete from public.site_feedback; delete from public.sites $$;

-- seed
insert into public.regions (name) values ('North'), ('South');
insert into public.inspectors (region_id, full_name, email) values (1, 'A. Rao', 'rao@example.com'), (2, 'B. Sen', 'sen@example.com');
insert into public.sites (region_id, address) values (1, '1 Main St'), (2, '2 Side Rd');
insert into public.inspection_notes (site_id, inspector_id, note) values (1, 1, 'ok'), (2, 2, 'crack in wall');
insert into public.site_feedback (site_id, reporter_email, message) values (1, 'x@example.com', 'noisy'), (2, 'y@example.com', 'blocked exit');
