create table public.products (
  id bigint generated always as identity primary key,
  name text not null,
  price_cents int not null
);
alter table public.products enable row level security;
create policy "products_public_read" on public.products for select to anon, authenticated using (true);

create table public.orders (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users(id),
  product_id bigint references public.products(id),
  shipping_address text
);
-- Policies written, but RLS never enabled on orders.
create policy "orders_read_own" on public.orders for select to authenticated using ((select auth.uid()) = user_id);
create policy "orders_insert_own" on public.orders for insert to authenticated with check ((select auth.uid()) = user_id);
