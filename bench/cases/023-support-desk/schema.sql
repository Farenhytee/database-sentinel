-- Multi-tenant support desk: orgs, tickets, replies, stats RPC.
create schema if not exists private;
grant usage on schema private to authenticated;

create table public.orgs (
  id uuid primary key default gen_random_uuid(),
  name text not null
);

create table public.org_members (
  org_id uuid not null references public.orgs(id),
  user_id uuid not null references auth.users(id),
  primary key (org_id, user_id)
);

create table public.tickets (
  id bigint generated always as identity primary key,
  org_id uuid not null references public.orgs(id),
  opened_by uuid not null references auth.users(id),
  subject text not null,
  body text not null,
  state text not null default 'open' check (state in ('open', 'pending', 'closed')),
  created_at timestamptz not null default now()
);

create table public.ticket_replies (
  id bigint generated always as identity primary key,
  ticket_id bigint not null references public.tickets(id),
  author_id uuid not null references auth.users(id),
  body text not null,
  created_at timestamptz not null default now()
);

create function private.is_org_member(o uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.org_members m
    where m.org_id = o and m.user_id = (select auth.uid())
  )
$$;

alter table public.orgs enable row level security;
alter table public.org_members enable row level security;
alter table public.tickets enable row level security;
alter table public.ticket_replies enable row level security;

create policy "orgs_member_read" on public.orgs for select to authenticated
  using (private.is_org_member(id));
create policy "org_members_read" on public.org_members for select to authenticated
  using (private.is_org_member(org_id));

create policy "tickets_member_read" on public.tickets for select to authenticated
  using (private.is_org_member(org_id));
create policy "tickets_member_open" on public.tickets for insert to authenticated
  with check (private.is_org_member(org_id) and (select auth.uid()) = opened_by);
create policy "tickets_member_update" on public.tickets for update to authenticated
  using (private.is_org_member(org_id)) with check (true);

create policy "replies_member_read" on public.ticket_replies for select to authenticated
  using (exists (select 1 from public.tickets t
                 where t.id = ticket_replies.ticket_id and private.is_org_member(t.org_id)));
create policy "replies_member_post" on public.ticket_replies for insert to authenticated
  with check ((select auth.uid()) = author_id
              and exists (select 1 from public.tickets t
                          where t.id = ticket_replies.ticket_id and private.is_org_member(t.org_id)));

-- Dashboard widget. Anon revoked; any signed-in user can pass any org id.
create function public.org_ticket_stats(p_org uuid) returns table (state text, ticket_count bigint)
language sql stable security definer set search_path = '' as $$
  select t.state, count(*) from public.tickets t where t.org_id = p_org group by t.state
$$;
revoke execute on function public.org_ticket_stats(uuid) from public, anon;
grant execute on function public.org_ticket_stats(uuid) to authenticated;

-- Nightly cron job only.
create function public.purge_closed_tickets(p_older_than interval) returns integer
language plpgsql security definer set search_path = '' as $$
declare n integer;
begin
  update public.tickets set body = '[purged]'
   where state = 'closed' and created_at < now() - p_older_than;
  get diagnostics n = row_count;
  return n;
end
$$;
revoke execute on function public.purge_closed_tickets(interval) from public, anon, authenticated;

-- seed
insert into public.orgs (id, name) values
  ('30000000-0000-0000-0000-000000000001', 'Northwind'),
  ('30000000-0000-0000-0000-000000000002', 'Globex');
insert into public.org_members (org_id, user_id) values
  ('30000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001'),
  ('30000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000002');
insert into public.tickets (org_id, opened_by, subject, body, state) values
  ('30000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001', 'Refund for order 1182', 'Customer charged twice', 'open'),
  ('30000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000002', 'SSO outage', 'Okta login loop since 09:00', 'pending');
insert into public.ticket_replies (ticket_id, author_id, body) values
  (1, '00000000-0000-0000-0000-000000000001', 'Refund issued'),
  (2, '00000000-0000-0000-0000-000000000002', 'Escalated to IdP vendor');
