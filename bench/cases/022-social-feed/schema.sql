-- Microblog: public profiles and posts, follow graph, personalised feed RPC.
create table public.profiles (
  id uuid primary key references auth.users(id),
  handle text not null unique,
  display_name text,
  avatar_path text
);
alter table public.profiles enable row level security;
create policy "profiles_public_read" on public.profiles for select to anon, authenticated using (true);
create policy "profiles_insert_self" on public.profiles for insert to authenticated
  with check ((select auth.uid()) = id);
create policy "profiles_update_self" on public.profiles for update to authenticated
  using ((select auth.uid()) = id) with check ((select auth.uid()) = id);

create table public.posts (
  id bigint generated always as identity primary key,
  author_id uuid not null references public.profiles(id),
  body text not null check (char_length(body) <= 500),
  created_at timestamptz not null default now()
);
alter table public.posts enable row level security;
-- All posts on this network are public.
create policy "posts_public_read" on public.posts for select to anon, authenticated using (true);
create policy "posts_insert_own" on public.posts for insert to authenticated
  with check ((select auth.uid()) = author_id);
create policy "posts_delete_own" on public.posts for delete to authenticated
  using ((select auth.uid()) = author_id);

create table public.follows (
  follower_id uuid not null references public.profiles(id),
  followee_id uuid not null references public.profiles(id),
  created_at timestamptz not null default now(),
  primary key (follower_id, followee_id)
);
alter table public.follows enable row level security;
create policy "follows_read_own" on public.follows for select to authenticated
  using ((select auth.uid()) = follower_id or (select auth.uid()) = followee_id);
create policy "follows_insert" on public.follows for insert to authenticated
  with check (true);
create policy "follows_delete_own" on public.follows for delete to authenticated
  using ((select auth.uid()) = follower_id);

-- Feed RPC: scoped to the caller, but definer rights with no pinned search_path.
create function public.get_feed(p_limit integer default 50) returns setof public.posts
language sql stable security definer as $$
  select p.* from public.posts p
  where p.author_id = (select auth.uid())
     or p.author_id in (select f.followee_id from public.follows f
                        where f.follower_id = (select auth.uid()))
  order by p.created_at desc
  limit p_limit
$$;

-- Pure helper.
create function public.normalize_handle(t text) returns text
language sql immutable set search_path = '' as $$
  select lower(regexp_replace(t, '[^a-zA-Z0-9_]', '', 'g'))
$$;

-- Avatars are public images.
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
create policy "avatars_owner_select" on storage.objects for select to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);
create policy "avatars_owner_insert" on storage.objects for insert to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);
create policy "avatars_owner_update" on storage.objects for update to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text)
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text);

-- seed
insert into public.profiles (id, handle, display_name) values
  ('00000000-0000-0000-0000-000000000001', 'alice', 'Alice'),
  ('00000000-0000-0000-0000-000000000002', 'bob', 'Bob');
insert into public.posts (author_id, body) values
  ('00000000-0000-0000-0000-000000000001', 'first post!'),
  ('00000000-0000-0000-0000-000000000002', 'hello from bob');
insert into public.follows (follower_id, followee_id) values
  ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001');
