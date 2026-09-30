create table public.doctors (
  id bigint generated always as identity primary key,
  name text not null,
  specialty text
);
alter table public.doctors enable row level security;
create policy "doctors_public_read" on public.doctors for select to anon, authenticated using (true);

create table public.appointments (
  id bigint generated always as identity primary key,
  patient_id uuid not null references auth.users(id),
  doctor_id bigint references public.doctors(id),
  reason text,
  starts_at timestamptz not null
);
alter table public.appointments enable row level security;
-- Meant for the calendar view; exposes every patient's visit reason to any logged-in user.
create policy "appointments_read" on public.appointments for select to authenticated using (true);
create policy "appointments_book" on public.appointments for insert
  with check ((select auth.uid()) = patient_id);

-- seed
insert into public.doctors (name, specialty) values ('Dr. Rao', 'cardiology'), ('Dr. Kim', 'dermatology');
insert into public.appointments (patient_id, doctor_id, reason, starts_at) values
  ('00000000-0000-0000-0000-000000000001', 1, 'chest pain', now()), ('00000000-0000-0000-0000-000000000002', 2, 'rash', now());
