create table public.messages (
  id bigint generated always as identity primary key,
  sender_id uuid not null references auth.users(id),
  recipient_id uuid not null references auth.users(id),
  body text
);
alter table public.messages enable row level security;
create policy "messages_read_own" on public.messages for select to authenticated
  using ((select auth.uid()) in (sender_id, recipient_id));
-- Left over from debugging; OR'd with the policy above, so every user reads every message.
create policy "messages_debug_read" on public.messages for select to authenticated using (true);
create policy "messages_send" on public.messages for insert to authenticated with check ((select auth.uid()) = sender_id);

create table public.integrations (
  id bigint generated always as identity primary key,
  owner_id uuid not null references auth.users(id),
  provider text not null,
  api_key text
);
alter table public.integrations enable row level security;
create policy "integrations_own" on public.integrations for all to authenticated
  using ((select auth.uid()) = owner_id) with check ((select auth.uid()) = owner_id);

-- seed
insert into public.messages (sender_id, recipient_id, body) values ('00000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002', 'hi bob'), ('00000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000001', 'hi alice');
insert into public.integrations (owner_id, provider, api_key) values ('00000000-0000-0000-0000-000000000001', 'stripe', 'fake_key_not_real');
