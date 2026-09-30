-- Online tutoring: public tutor directory, private 1:1 sessions, recordings in storage.
create table public.tutors (
  id uuid primary key references auth.users(id),
  display_name text not null,
  subjects text[] not null default '{}',
  hourly_rate_cents integer not null
);
alter table public.tutors enable row level security;
-- Public directory.
create policy "tutors_directory_read" on public.tutors for select to anon, authenticated using (true);

create table public.sessions (
  id bigint generated always as identity primary key,
  tutor_id uuid not null references public.tutors(id),
  student_id uuid not null references auth.users(id),
  starts_at timestamptz not null,
  topic text not null,
  progress_notes text
);
alter table public.sessions enable row level security;
-- Tutor access keyed off user_metadata, which any user can set on themselves.
create policy "sessions_read" on public.sessions for select to authenticated
  using (
    (select auth.uid()) = student_id
    or ((select auth.jwt()) -> 'user_metadata' ->> 'account_type') = 'tutor'
  );
create policy "sessions_book" on public.sessions for insert to authenticated
  with check ((select auth.uid()) = student_id);
create policy "sessions_cancel" on public.sessions for delete to authenticated
  using ((select auth.uid()) = student_id);

-- Headshots are public marketing assets; recordings are private lesson videos.
insert into storage.buckets (id, name, public) values
  ('tutor-headshots', 'tutor-headshots', true),
  ('session-recordings', 'session-recordings', true);

create policy "recordings_owner_read" on storage.objects for select to authenticated
  using (bucket_id = 'session-recordings' and (storage.foldername(name))[1] = (select auth.uid())::text);
create policy "recordings_owner_upload" on storage.objects for insert to authenticated
  with check (bucket_id = 'session-recordings' and (storage.foldername(name))[1] = (select auth.uid())::text);

-- seed
insert into public.tutors (id, display_name, subjects, hourly_rate_cents) values
  ('00000000-0000-0000-0000-000000000001', 'Alice (Maths)', '{algebra,calculus}', 4500);
insert into public.sessions (tutor_id, student_id, starts_at, topic, progress_notes) values
  ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002', '2026-10-02 16:00+00', 'Integration by parts', 'Struggles with substitution; parent requested weekly report'),
  ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002', '2026-10-09 16:00+00', 'Series convergence', null);
