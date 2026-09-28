create table public.documents (
  id bigint generated always as identity primary key,
  owner_id uuid not null references auth.users(id),
  storage_path text not null
);
alter table public.documents enable row level security;
create policy "documents_own" on public.documents for all to authenticated
  using ((select auth.uid()) = owner_id) with check ((select auth.uid()) = owner_id);

insert into storage.buckets (id, name, public) values
  ('avatars', 'avatars', true),   -- public profile pictures: intended
  ('invoices', 'invoices', true); -- customer invoices: should be private
