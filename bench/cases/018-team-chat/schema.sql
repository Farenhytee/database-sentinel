-- Workspace chat (channels + messages).
create schema if not exists private;
grant usage on schema private to authenticated;

create table public.workspaces (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_at timestamptz not null default now()
);

create table public.workspace_members (
  workspace_id uuid not null references public.workspaces(id),
  user_id uuid not null references auth.users(id),
  member_kind text not null default 'guest' check (member_kind in ('owner', 'admin', 'member', 'guest')),
  notify_level text not null default 'mentions' check (notify_level in ('all', 'mentions', 'none')),
  primary key (workspace_id, user_id)
);

create table public.channels (
  id bigint generated always as identity primary key,
  workspace_id uuid not null references public.workspaces(id),
  name text not null,
  last_message_at timestamptz
);

create table public.messages (
  id bigint generated always as identity primary key,
  workspace_id uuid not null references public.workspaces(id),
  channel_id bigint not null references public.channels(id),
  author_id uuid not null references auth.users(id),
  body text not null,
  is_pinned boolean not null default false,
  sent_at timestamptz not null default now()
);

-- Policy helper; private schema is not exposed via the API.
create function private.is_workspace_member(ws uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.workspace_members m
    where m.workspace_id = ws and m.user_id = (select auth.uid())
  )
$$;

alter table public.workspaces enable row level security;
alter table public.workspace_members enable row level security;
alter table public.channels enable row level security;
alter table public.messages enable row level security;

create policy "workspaces_member_read" on public.workspaces for select to authenticated
  using (private.is_workspace_member(id));

create policy "members_read" on public.workspace_members for select to authenticated
  using (private.is_workspace_member(workspace_id));
-- For notify_level; also lets a guest set member_kind = 'owner'.
create policy "members_update_own" on public.workspace_members for update to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);

create policy "channels_member_read" on public.channels for select to authenticated
  using (private.is_workspace_member(workspace_id));

create policy "messages_member_read" on public.messages for select to authenticated
  using (private.is_workspace_member(workspace_id));
-- Intended as "pinned messages in your workspace"; OR'd with the above, it exposes every workspace's pins.
create policy "messages_pinned_read" on public.messages for select to authenticated
  using (is_pinned);
create policy "messages_post" on public.messages for insert to authenticated
  with check ((select auth.uid()) = author_id and private.is_workspace_member(workspace_id));

-- Trigger-only (not callable via /rpc), but SECURITY DEFINER without a pinned search_path.
create function public.touch_channel_activity() returns trigger
language plpgsql security definer as $$
begin
  update public.channels set last_message_at = new.sent_at where id = new.channel_id;
  return new;
end
$$;
create trigger messages_touch_channel after insert on public.messages
  for each row execute function public.touch_channel_activity();

-- seed
insert into public.workspaces (id, name) values
  ('10000000-0000-0000-0000-000000000001', 'Acme Corp'),
  ('10000000-0000-0000-0000-000000000002', 'Bob''s Side Project');
insert into public.workspace_members (workspace_id, user_id, member_kind) values
  ('10000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001', 'owner'),
  ('10000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002', 'guest'),
  ('10000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000002', 'owner');
insert into public.channels (workspace_id, name) values
  ('10000000-0000-0000-0000-000000000001', 'general'),
  ('10000000-0000-0000-0000-000000000002', 'launch');
insert into public.messages (workspace_id, channel_id, author_id, body, is_pinned) values
  ('10000000-0000-0000-0000-000000000001', 1, '00000000-0000-0000-0000-000000000001', 'Q4 layoffs list is in the board deck, do not share', true),
  ('10000000-0000-0000-0000-000000000001', 1, '00000000-0000-0000-0000-000000000002', 'hi all', false),
  ('10000000-0000-0000-0000-000000000002', 2, '00000000-0000-0000-0000-000000000002', 'launch date: Nov 3', true);
