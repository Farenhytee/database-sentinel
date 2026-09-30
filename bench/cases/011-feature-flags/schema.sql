-- Flags meant to be read by the app; RLS turned on but nobody wrote policies.
create table public.feature_flags (
  key text primary key,
  enabled boolean not null default false
);
alter table public.feature_flags enable row level security;

-- Public site settings, readable by everyone on purpose... but the payment key sits in the same table.
create table public.app_settings (
  id int primary key,
  site_name text not null,
  support_email text,
  stripe_key text
);
alter table public.app_settings enable row level security;
create policy "settings_public_read" on public.app_settings for select to anon, authenticated using (true);

-- seed
insert into public.feature_flags (key, enabled) values ('new_checkout', true);
insert into public.app_settings (id, site_name, support_email, stripe_key) values (1, 'Shop', 'help@example.invalid', 'fake_sk_not_real');
