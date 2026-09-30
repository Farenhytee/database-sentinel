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

-- seed
insert into public.documents (owner_id, storage_path) values ('00000000-0000-0000-0000-000000000001', 'a/contract.pdf'), ('00000000-0000-0000-0000-000000000002', 'b/id.png');
