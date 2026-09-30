create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text,
  email text,
  phone text
);
alter table public.profiles enable row level security;
create policy "profiles_read_own" on public.profiles for select to authenticated using ((select auth.uid()) = id);

-- Meant to show usernames only; runs as owner, so it bypasses RLS and leaks email/phone.
create view public.profile_directory as select id, username, email, phone from public.profiles;

create table public.scores (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id),
  points int not null
);
alter table public.scores enable row level security;
create policy "scores_read_own" on public.scores for select to authenticated using ((select auth.uid()) = user_id);
create materialized view public.leaderboard as select user_id, sum(points) as total from public.scores group by user_id;

-- seed
insert into public.profiles (id, username, email, phone) values ('00000000-0000-0000-0000-000000000001', 'alice', 'alice@example.invalid', '555-0101'), ('00000000-0000-0000-0000-000000000002', 'bob', 'bob@example.invalid', '555-0102');
insert into public.scores (user_id, points) values ('00000000-0000-0000-0000-000000000001', 10), ('00000000-0000-0000-0000-000000000002', 7);
refresh materialized view public.leaderboard;
