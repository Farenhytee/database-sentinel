create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  bio text,
  subscription_tier text default 'free',
  is_staff boolean default false
);
alter table public.profiles enable row level security;
create policy "profiles_read_own" on public.profiles for select to authenticated using ((select auth.uid()) = id);
-- Row-scoped correctly, but every column (incl. tier/staff flag) is updatable.
create policy "profiles_update_own" on public.profiles for update to authenticated
  using ((select auth.uid()) = id) with check ((select auth.uid()) = id);

create table public.teams (
  id bigint generated always as identity primary key,
  owner_id uuid not null references auth.users(id),
  name text not null
);
alter table public.teams enable row level security;
create policy "teams_owner_all" on public.teams for all to authenticated
  using ((select auth.uid()) = owner_id) with check ((select auth.uid()) = owner_id);
