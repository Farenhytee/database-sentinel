-- Virtual running challenges: join a challenge, log check-ins, earn a finisher medal.
create table public.challenges (
  id bigint generated always as identity primary key,
  organizer_id uuid not null references auth.users(id),
  title text not null,
  distance_km numeric(6,1) not null,
  is_published boolean not null default false
);
alter table public.challenges enable row level security;
-- Published challenges are a public catalog.
create policy "challenges_read" on public.challenges for select to anon, authenticated
  using (is_published or (select auth.uid()) = organizer_id);

create table public.participants (
  id bigint generated always as identity primary key,
  challenge_id bigint not null references public.challenges(id),
  user_id uuid not null references auth.users(id),
  joined_at timestamptz not null default now(),
  finished_at timestamptz,
  medal_code text,
  unique (challenge_id, user_id)
);
alter table public.participants enable row level security;
-- Joining happens server-side after entry-fee payment.
create policy "participants_read_own" on public.participants for select to authenticated
  using ((select auth.uid()) = user_id);

create table public.check_ins (
  id bigint generated always as identity primary key,
  challenge_id bigint not null references public.challenges(id),
  user_id uuid not null references auth.users(id),
  km numeric(5,2) not null check (km > 0),
  logged_at timestamptz not null default now(),
  note text
);
alter table public.check_ins enable row level security;
-- No TO clause.
create policy "check_ins_read" on public.check_ins for select
  using ((select auth.uid()) = user_id);
create policy "check_ins_log" on public.check_ins for insert to authenticated
  with check (
    (select auth.uid()) = user_id
    and exists (select 1 from public.participants p
                where p.challenge_id = check_ins.challenge_id and p.user_id = (select auth.uid()))
  );

-- Standings board; default (owner-rights) view over RLS-protected tables.
create view public.challenge_standings as
  select p.challenge_id, p.user_id, coalesce(sum(c.km), 0) as total_km, p.finished_at
  from public.participants p
  left join public.check_ins c on c.challenge_id = p.challenge_id and c.user_id = p.user_id
  group by p.challenge_id, p.user_id, p.finished_at;

-- Called by the app when a runner hits the distance; no caller check.
create function public.grant_finisher_medal(p_participant_id bigint) returns text
language plpgsql security definer set search_path = '' as $$
declare
  code text := 'MEDAL-' || p_participant_id || '-' || to_char(now(), 'YYYYMMDD');
begin
  update public.participants
     set finished_at = now(), medal_code = code
   where id = p_participant_id;
  return code;
end
$$;

-- seed
insert into public.challenges (organizer_id, title, distance_km, is_published) values
  ('00000000-0000-0000-0000-000000000001', 'October 100K', 100.0, true),
  ('00000000-0000-0000-0000-000000000001', 'Winter Draft Challenge', 50.0, false);
insert into public.participants (challenge_id, user_id) values
  (1, '00000000-0000-0000-0000-000000000001'),
  (1, '00000000-0000-0000-0000-000000000002');
insert into public.check_ins (challenge_id, user_id, km, note) values
  (1, '00000000-0000-0000-0000-000000000001', 12.5, 'Park loop'),
  (1, '00000000-0000-0000-0000-000000000002', 8.0, 'Knee sore, took it easy');
