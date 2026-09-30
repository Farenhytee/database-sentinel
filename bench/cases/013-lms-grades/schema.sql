create table public.courses (
  id bigint generated always as identity primary key,
  title text not null,
  published boolean default false
);
alter table public.courses enable row level security;
create policy "courses_read_published" on public.courses for select to anon, authenticated using (published);

create table public.enrollments (
  id bigint generated always as identity primary key,
  student_id uuid not null references auth.users(id),
  course_id bigint references public.courses(id),
  completed_lessons int default 0,
  final_grade text,
  certified boolean default false
);
alter table public.enrollments enable row level security;
create policy "enrollments_read_own" on public.enrollments for select to authenticated using ((select auth.uid()) = student_id);
-- Students update their progress; nothing stops them setting final_grade or certified.
create policy "enrollments_update_own" on public.enrollments for update to authenticated
  using ((select auth.uid()) = student_id) with check ((select auth.uid()) = student_id);

-- Callable by anyone via /rpc; certifies any enrollment id.
create function public.award_certificate(enrollment_id bigint) returns void
language sql security definer set search_path = '' as $$
  update public.enrollments set certified = true where id = enrollment_id
$$;

-- seed
insert into public.courses (title, published) values ('SQL 101', true), ('Draft course', false);
insert into public.enrollments (student_id, course_id, completed_lessons) values ('00000000-0000-0000-0000-000000000001', 1, 3), ('00000000-0000-0000-0000-000000000002', 1, 1);
