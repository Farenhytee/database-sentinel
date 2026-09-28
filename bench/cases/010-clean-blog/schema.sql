create schema if not exists private;

create function private.is_admin() returns boolean
language sql stable security definer set search_path = '' as $$
  select coalesce((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin', false)
$$;
grant usage on schema private to authenticated;

create table public.posts (
  id bigint generated always as identity primary key,
  author_id uuid not null references auth.users(id),
  title text not null,
  body text,
  published boolean default false
);
alter table public.posts enable row level security;
create policy "posts_read" on public.posts for select to anon, authenticated using (published);
create policy "posts_insert_own" on public.posts for insert to authenticated with check ((select auth.uid()) = author_id);
create policy "posts_update_own" on public.posts for update to authenticated
  using ((select auth.uid()) = author_id) with check ((select auth.uid()) = author_id);

create table public.audit_log (
  id bigint generated always as identity primary key,
  actor uuid,
  action text,
  at timestamptz default now()
);
alter table public.audit_log enable row level security;
create policy "audit_admin_read" on public.audit_log for select to authenticated using ((select private.is_admin()));
