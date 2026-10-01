-- Learning app modeled on a real project: owner-scoped UPDATE policies without WITH CHECK.
-- Postgres reuses USING as the check, so user_id can't be reassigned: only the quota table is a finding.
create table public.user_profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  first_name text,
  last_name text,
  grade text,
  school_id bigint
);
alter table public.user_profiles enable row level security;
create policy "Users can read own profile" on public.user_profiles for select to authenticated using ((select auth.uid()) = user_id);
create policy "Users can update own profile" on public.user_profiles for update to authenticated using ((select auth.uid()) = user_id);

create table public.practice_sessions (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id),
  conversation_transcript text,
  feedback_summary text
);
alter table public.practice_sessions enable row level security;
create policy "Users can read own sessions" on public.practice_sessions for select to authenticated using ((select auth.uid()) = user_id);
create policy "Users can insert own sessions" on public.practice_sessions for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "Users can update own sessions" on public.practice_sessions for update to authenticated using ((select auth.uid()) = user_id);

create table public.user_skill_progress (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id),
  skill text not null,
  is_completed boolean default false,
  current_flow_step int default 0
);
alter table public.user_skill_progress enable row level security;
create policy "Users can read own progress" on public.user_skill_progress for select to authenticated using ((select auth.uid()) = user_id);
create policy "Users can update own progress" on public.user_skill_progress for update to authenticated using ((select auth.uid()) = user_id);

-- Paid quota: users can top up their own remaining sessions.
create table public.user_usage (
  user_id uuid primary key references auth.users(id) on delete cascade,
  quick_available int not null default 3,
  full_available int not null default 1
);
alter table public.user_usage enable row level security;
create policy "usage_read_own" on public.user_usage for select to authenticated using (user_id = (select auth.uid()));
create policy "usage_update_own" on public.user_usage for update to authenticated using (user_id = (select auth.uid()));

-- seed
insert into public.user_profiles (user_id, first_name) values ('00000000-0000-0000-0000-000000000001', 'Alice'), ('00000000-0000-0000-0000-000000000002', 'Bob');
insert into public.practice_sessions (user_id, feedback_summary) values ('00000000-0000-0000-0000-000000000001', 'good');
insert into public.user_skill_progress (user_id, skill) values ('00000000-0000-0000-0000-000000000001', 'grammar');
insert into public.user_usage (user_id) values ('00000000-0000-0000-0000-000000000001'), ('00000000-0000-0000-0000-000000000002');
