-- Applied before every case's schema.sql. Reference these ids in case seed rows.
insert into auth.users (id, email) values
  ('00000000-0000-0000-0000-000000000001', 'alice@example.invalid'),
  ('00000000-0000-0000-0000-000000000002', 'bob@example.invalid');
