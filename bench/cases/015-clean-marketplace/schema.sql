create table public.listings (
  id bigint generated always as identity primary key,
  seller_id uuid not null references auth.users(id),
  title text not null,
  price_cents int not null,
  active boolean default true,
  is_featured boolean default false
);
alter table public.listings enable row level security;
create policy "listings_public_read" on public.listings for select to anon, authenticated using (active);
create policy "listings_insert_own" on public.listings for insert to authenticated with check ((select auth.uid()) = seller_id);
create policy "listings_update_own" on public.listings for update to authenticated
  using ((select auth.uid()) = seller_id) with check ((select auth.uid()) = seller_id);
-- Featured placement is paid: not client-writable.
revoke update on public.listings from anon, authenticated;
grant update (title, price_cents, active) on public.listings to authenticated;

create table public.purchases (
  id bigint generated always as identity primary key,
  buyer_id uuid not null references auth.users(id),
  listing_id bigint references public.listings(id)
);
alter table public.purchases enable row level security;
create policy "purchases_read_own" on public.purchases for select to authenticated using ((select auth.uid()) = buyer_id);
create policy "purchases_insert_own" on public.purchases for insert to authenticated with check ((select auth.uid()) = buyer_id);

create function public.bump_listing_count() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  return new;
end $$;
revoke execute on function public.bump_listing_count() from public, anon, authenticated;
create trigger listings_count after insert on public.listings for each row execute function public.bump_listing_count();

insert into storage.buckets (id, name, public) values ('listing-images', 'listing-images', true);

-- seed
insert into public.listings (seller_id, title, price_cents) values ('00000000-0000-0000-0000-000000000001', 'Bike', 15000), ('00000000-0000-0000-0000-000000000002', 'Desk', 8000);
insert into public.purchases (buyer_id, listing_id) values ('00000000-0000-0000-0000-000000000002', 1);
