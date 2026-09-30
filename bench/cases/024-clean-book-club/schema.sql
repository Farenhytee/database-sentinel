-- Book club: public catalog and reviews, profiles with column-limited updates, public avatars.
create table public.profiles (
  id uuid primary key references auth.users(id),
  display_name text not null,
  bio text,
  is_moderator boolean not null default false
);
alter table public.profiles enable row level security;
create policy "profiles_public_read" on public.profiles for select to anon, authenticated using (true);
create policy "profiles_update_self" on public.profiles for update to authenticated
  using ((select auth.uid()) = id) with check ((select auth.uid()) = id);
-- Users may only edit display_name and bio; is_moderator is not updatable.
revoke update on public.profiles from anon, authenticated;
grant update (display_name, bio) on public.profiles to authenticated;

-- Trigger-only profile bootstrap.
create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, display_name) values (new.id, split_part(new.email, '@', 1));
  return new;
end
$$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

create table public.books (
  id bigint generated always as identity primary key,
  title text not null,
  author_name text not null,
  published_year integer
);
alter table public.books enable row level security;
-- Public catalog, curated by staff via the dashboard.
create policy "books_catalog_read" on public.books for select to anon, authenticated using (true);

create table public.reviews (
  id bigint generated always as identity primary key,
  book_id bigint not null references public.books(id),
  reviewer_id uuid not null references public.profiles(id),
  rating smallint not null check (rating between 1 and 5),
  body text,
  created_at timestamptz not null default now(),
  unique (book_id, reviewer_id)
);
alter table public.reviews enable row level security;
-- Reviews are published content.
create policy "reviews_public_read" on public.reviews for select to anon, authenticated using (true);
create policy "reviews_insert_own" on public.reviews for insert to authenticated
  with check ((select auth.uid()) = reviewer_id);
create policy "reviews_update_own" on public.reviews for update to authenticated
  using ((select auth.uid()) = reviewer_id) with check ((select auth.uid()) = reviewer_id);
create policy "reviews_delete_own" on public.reviews for delete to authenticated
  using ((select auth.uid()) = reviewer_id);

-- Public avatar images; writes restricted to the owner's folder.
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
create policy "avatars_owner_select" on storage.objects for select to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);
create policy "avatars_owner_insert" on storage.objects for insert to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);
create policy "avatars_owner_update" on storage.objects for update to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text)
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);
create policy "avatars_owner_delete" on storage.objects for delete to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);

-- seed (alice/bob predate the trigger, so profiles are inserted directly)
insert into public.profiles (id, display_name, bio, is_moderator) values
  ('00000000-0000-0000-0000-000000000001', 'alice', 'Sci-fi and slow mornings', true),
  ('00000000-0000-0000-0000-000000000002', 'bob', null, false);
insert into public.books (title, author_name, published_year) values
  ('The Left Hand of Darkness', 'Ursula K. Le Guin', 1969),
  ('Piranesi', 'Susanna Clarke', 2020);
insert into public.reviews (book_id, reviewer_id, rating, body) values
  (1, '00000000-0000-0000-0000-000000000001', 5, 'A classic.'),
  (2, '00000000-0000-0000-0000-000000000002', 4, 'Dreamlike.');
