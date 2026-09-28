create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id),
  body text
);
alter table public.notes enable row level security;
create policy "notes_own" on public.notes for all to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);

-- Leaks every user's email to anyone via /rpc/get_user_emails.
create function public.get_user_emails() returns table(email text)
language sql security definer as $$ select email::text from auth.users $$;

-- Pure helper: fine to expose.
create function public.slugify(t text) returns text
language sql immutable set search_path = '' as $$ select lower(regexp_replace(t, '[^a-zA-Z0-9]+', '-', 'g')) $$;

-- Invoker rights + auth check: fine.
create function public.delete_my_notes() returns void
language sql set search_path = '' as $$ delete from public.notes where user_id = (select auth.uid()) $$;
