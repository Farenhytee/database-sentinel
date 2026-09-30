create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  avatar_url text
);
alter table public.profiles enable row level security;
create policy "profiles_read_own" on public.profiles for select to authenticated using ((select auth.uid()) = id);
create policy "profiles_update_own" on public.profiles for update to authenticated
  using ((select auth.uid()) = id) with check ((select auth.uid()) = id);

create table public.todos (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id),
  title text not null,
  done boolean default false
);
-- Created via migration; RLS never enabled.

-- seed
insert into public.profiles (id, display_name) values ('00000000-0000-0000-0000-000000000001', 'Alice'), ('00000000-0000-0000-0000-000000000002', 'Bob');
insert into public.todos (user_id, title) values ('00000000-0000-0000-0000-000000000001', 'buy milk'), ('00000000-0000-0000-0000-000000000002', 'call mom');
