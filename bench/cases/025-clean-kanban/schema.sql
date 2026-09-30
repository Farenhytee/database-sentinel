-- Kanban boards: membership-scoped cards, public templates, revoked maintenance RPC.
create schema if not exists private;
grant usage on schema private to authenticated;

create table public.board_templates (
  id bigint generated always as identity primary key,
  name text not null,
  lanes text[] not null
);
alter table public.board_templates enable row level security;
-- Public template gallery.
create policy "templates_public_read" on public.board_templates for select to anon, authenticated using (true);

create table public.boards (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id),
  name text not null,
  card_count integer not null default 0
);

create table public.board_members (
  board_id uuid not null references public.boards(id),
  user_id uuid not null references auth.users(id),
  role text not null default 'editor' check (role in ('owner', 'editor', 'viewer')),
  primary key (board_id, user_id)
);

create table public.cards (
  id bigint generated always as identity primary key,
  board_id uuid not null references public.boards(id),
  title text not null,
  details text,
  lane text not null default 'todo',
  position integer not null default 0,
  assignee_id uuid references auth.users(id),
  done boolean not null default false,
  archived boolean not null default false
);

create function private.is_board_member(b uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.board_members m
    where m.board_id = b and m.user_id = (select auth.uid())
  )
$$;

alter table public.boards enable row level security;
alter table public.board_members enable row level security;
alter table public.cards enable row level security;

create policy "boards_member_read" on public.boards for select to authenticated
  using (private.is_board_member(id));
create policy "boards_owner_insert" on public.boards for insert to authenticated
  with check ((select auth.uid()) = owner_id);
create policy "boards_owner_update" on public.boards for update to authenticated
  using ((select auth.uid()) = owner_id) with check ((select auth.uid()) = owner_id);
create policy "boards_owner_delete" on public.boards for delete to authenticated
  using ((select auth.uid()) = owner_id);
-- Only the name is user-editable; card_count is maintained server-side.
revoke update on public.boards from anon, authenticated;
grant update (name) on public.boards to authenticated;

-- Membership is managed server-side; members can see who else is on the board.
create policy "board_members_read" on public.board_members for select to authenticated
  using (private.is_board_member(board_id));

create policy "cards_member_all" on public.cards for all to authenticated
  using (private.is_board_member(board_id)) with check (private.is_board_member(board_id));

-- Trigger-only: creator becomes owner member.
create function public.add_board_owner() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.board_members (board_id, user_id, role) values (new.id, new.owner_id, 'owner');
  return new;
end
$$;
create trigger boards_add_owner after insert on public.boards
  for each row execute function public.add_board_owner();

-- Maintenance job only; not callable by API roles.
create function public.recount_board_cards(p_board uuid) returns void
language sql security definer set search_path = '' as $$
  update public.boards b
     set card_count = (select count(*) from public.cards c where c.board_id = p_board and not c.archived)
   where b.id = p_board
$$;
revoke execute on function public.recount_board_cards(uuid) from public, anon, authenticated;

-- Invoker rights + explicit auth check.
create function public.archive_done_cards(p_board uuid) returns integer
language plpgsql set search_path = '' as $$
declare n integer;
begin
  if (select auth.uid()) is null or not private.is_board_member(p_board) then
    raise exception 'not a board member';
  end if;
  update public.cards set archived = true where board_id = p_board and done and not archived;
  get diagnostics n = row_count;
  return n;
end
$$;

create view public.my_open_cards with (security_invoker = true) as
  select c.id, c.board_id, c.title, c.lane
  from public.cards c
  where c.assignee_id = (select auth.uid()) and not c.done and not c.archived;

-- seed (trigger adds each owner to board_members)
insert into public.board_templates (name, lanes) values
  ('Basic', '{todo,doing,done}'),
  ('Sprint', '{backlog,todo,in_review,done}');
insert into public.boards (id, owner_id, name) values
  ('40000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000001', 'Website relaunch'),
  ('40000000-0000-0000-0000-000000000002', '00000000-0000-0000-0000-000000000002', 'Bob personal');
insert into public.board_members (board_id, user_id, role) values
  ('40000000-0000-0000-0000-000000000001', '00000000-0000-0000-0000-000000000002', 'editor');
insert into public.cards (board_id, title, lane, assignee_id, done) values
  ('40000000-0000-0000-0000-000000000001', 'Draft hero copy', 'doing', '00000000-0000-0000-0000-000000000002', false),
  ('40000000-0000-0000-0000-000000000001', 'Pick fonts', 'done', '00000000-0000-0000-0000-000000000001', true),
  ('40000000-0000-0000-0000-000000000002', 'Renew passport', 'todo', '00000000-0000-0000-0000-000000000002', false);
