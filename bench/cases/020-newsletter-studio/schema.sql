-- Newsletter authoring + sending (bring-your-own SMTP).
create table public.newsletters (
  id bigint generated always as identity primary key,
  owner_id uuid not null references auth.users(id),
  title text not null
);
alter table public.newsletters enable row level security;
create policy "newsletters_owner" on public.newsletters for all to authenticated
  using ((select auth.uid()) = owner_id) with check ((select auth.uid()) = owner_id);

create table public.issues (
  id bigint generated always as identity primary key,
  newsletter_id bigint not null references public.newsletters(id),
  subject text not null,
  body_md text not null,
  sent_at timestamptz
);
alter table public.issues enable row level security;
create policy "issues_owner" on public.issues for all to authenticated
  using (exists (select 1 from public.newsletters n
                 where n.id = issues.newsletter_id and n.owner_id = (select auth.uid())))
  with check (exists (select 1 from public.newsletters n
                      where n.id = issues.newsletter_id and n.owner_id = (select auth.uid())));

-- Open-tracking pixel log.
create table public.issue_opens (
  id bigint generated always as identity primary key,
  issue_id bigint not null references public.issues(id),
  opened_at timestamptz not null default now(),
  mail_client text
);

create table public.sending_settings (
  owner_id uuid primary key references auth.users(id),
  smtp_host text not null,
  smtp_port integer not null default 587,
  smtp_username text not null,
  smtp_password text not null,
  from_name text
);
alter table public.sending_settings enable row level security;
create policy "sending_settings_owner" on public.sending_settings for all to authenticated
  using ((select auth.uid()) = owner_id) with check ((select auth.uid()) = owner_id);

-- seed
insert into public.newsletters (owner_id, title) values
  ('00000000-0000-0000-0000-000000000001', 'Alice''s Weekly Market Notes'),
  ('00000000-0000-0000-0000-000000000002', 'Bob on Bikes');
insert into public.issues (newsletter_id, subject, body_md, sent_at) values
  (1, 'Issue #1', '# Hello subscribers', '2026-09-01 08:00+00'),
  (2, 'Draft: fork review', 'Unpublished draft', null);
insert into public.issue_opens (issue_id, mail_client) values (1, 'Apple Mail'), (1, 'Gmail');
insert into public.sending_settings (owner_id, smtp_host, smtp_username, smtp_password, from_name) values
  ('00000000-0000-0000-0000-000000000001', 'smtp.example.invalid', 'alice', 'fake-smtp-pass-alice', 'Alice'),
  ('00000000-0000-0000-0000-000000000002', 'smtp.example.invalid', 'bob', 'fake-smtp-pass-bob', 'Bob');
