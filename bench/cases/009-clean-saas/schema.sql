create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text,
  avatar_url text,
  plan text default 'free'
);
alter table public.profiles enable row level security;
create policy "profiles_read_own" on public.profiles for select to authenticated using ((select auth.uid()) = id);
create policy "profiles_update_own" on public.profiles for update to authenticated
  using ((select auth.uid()) = id) with check ((select auth.uid()) = id);
-- Billing column is not client-writable.
revoke update on public.profiles from authenticated, anon;
grant update (display_name, avatar_url) on public.profiles to authenticated;

create table public.products (
  id bigint generated always as identity primary key,
  name text not null,
  price_cents int not null
);
alter table public.products enable row level security;
create policy "products_public_read" on public.products for select to anon, authenticated using (true);

-- Standard signup trigger: SECURITY DEFINER but not callable via /rpc.
create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id) values (new.id);
  return new;
end $$;
revoke execute on function public.handle_new_user() from public, anon, authenticated;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();

create function public.slugify(t text) returns text
language sql immutable set search_path = '' as $$ select lower(regexp_replace(t, '[^a-zA-Z0-9]+', '-', 'g')) $$;

insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
