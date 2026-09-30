create table public.tenants (
  id bigint generated always as identity primary key,
  name text not null
);
create table public.memberships (
  user_id uuid not null references auth.users(id),
  tenant_id bigint not null references public.tenants(id),
  primary key (user_id, tenant_id)
);
alter table public.tenants enable row level security;
alter table public.memberships enable row level security;
create policy "memberships_read_own" on public.memberships for select to authenticated using ((select auth.uid()) = user_id);
create policy "tenants_read_member" on public.tenants for select to authenticated
  using (id in (select tenant_id from public.memberships where user_id = (select auth.uid())));

create table public.invoices (
  id bigint generated always as identity primary key,
  tenant_id bigint not null references public.tenants(id),
  amount_cents int not null
);
alter table public.invoices enable row level security;
create policy "invoices_read_member" on public.invoices for select to authenticated
  using (tenant_id in (select tenant_id from public.memberships where user_id = (select auth.uid())));

create table public.invoice_items (
  id bigint generated always as identity primary key,
  invoice_id bigint not null references public.invoices(id),
  description text
);
-- Policy written, RLS never enabled.
create policy "items_read_member" on public.invoice_items for select to authenticated
  using (invoice_id in (select i.id from public.invoices i));

-- Dashboard helper: runs as owner, so every tenant's totals leak.
create view public.tenant_invoice_totals as
  select tenant_id, sum(amount_cents) as total_cents from public.invoices group by tenant_id;

insert into storage.buckets (id, name, public) values
  ('invoice-pdfs', 'invoice-pdfs', false),
  ('exports', 'exports', true);  -- nightly CSV exports of all invoices

-- seed
insert into public.tenants (name) values ('Acme'), ('Globex');
insert into public.memberships (user_id, tenant_id) values ('00000000-0000-0000-0000-000000000001', 1), ('00000000-0000-0000-0000-000000000002', 2);
insert into public.invoices (tenant_id, amount_cents) values (1, 10000), (2, 25000);
insert into public.invoice_items (invoice_id, description) values (1, 'consulting'), (2, 'licenses');
