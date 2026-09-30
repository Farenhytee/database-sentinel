create table public.posts (
  id bigint generated always as identity primary key,
  author_id uuid not null references auth.users(id),
  body text,
  published boolean default false
);
alter table public.posts enable row level security;
create policy "posts_read_published" on public.posts for select to anon, authenticated using (published);
create policy "posts_write_own" on public.posts for insert to authenticated with check ((select auth.uid()) = author_id);
-- Admin check trusts user-editable metadata; no TO clause either.
create policy "posts_admin_delete" on public.posts for delete
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');

-- seed
insert into public.posts (author_id, body, published) values ('00000000-0000-0000-0000-000000000001', 'hello', true), ('00000000-0000-0000-0000-000000000002', 'draft', false);
