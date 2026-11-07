-- Foxglove initial schema. Run in Supabase SQL Editor.
create extension if not exists pgcrypto;
create table if not exists public.households (
 id uuid primary key default gen_random_uuid(),
 name text not null,
 created_by uuid not null references auth.users(id),
 created_at timestamptz not null default now()
);
create table if not exists public.household_members (
 household_id uuid not null references public.households(id) on delete cascade,
 user_id uuid not null references auth.users(id) on delete cascade,
 role text not null default 'member' check(role in ('owner','member')),
 primary key(household_id,user_id)
);
create table if not exists public.products (
 id uuid primary key default gen_random_uuid(),
 brand text not null, name text not null, category text not null,
 sku text, vendor_url text, price_usd numeric(12,2),
 calories_per_unit numeric, protein_g_per_unit numeric,
 dimensions_cm jsonb, nutrition jsonb not null default '{}'::jsonb,
 specifications jsonb not null default '{}'::jsonb,
 model_data jsonb not null default '{}'::jsonb,
 verification_status text not null default 'unverified',
 created_at timestamptz not null default now()
);
create table if not exists public.inventory (
 id uuid primary key default gen_random_uuid(),
 household_id uuid not null references public.households(id) on delete cascade,
 product_id uuid references public.products(id),
 custom_name text, category text not null,
 quantity numeric not null default 1 check(quantity >= 0),
 status text not null default 'planned' check(status in ('planned','ordered','received','stored','consumed')),
 purchase_price numeric(12,2), actual_calories numeric, gallons numeric,
 location text, expiration_date date, notes text,
 created_at timestamptz not null default now()
);
create table if not exists public.simulations (
 id uuid primary key default gen_random_uuid(),
 household_id uuid not null references public.households(id) on delete cascade,
 day integer not null default 0,
 snapshot jsonb not null default '{}'::jsonb,
 created_at timestamptz not null default now()
);
-- Membership checks use a security-definer function to avoid recursive RLS.
create or replace function public.is_household_member(h uuid)
returns boolean language sql stable security definer set search_path = ''
as $$select exists(select 1 from public.household_members m where m.household_id=h and m.user_id=(select auth.uid()))$$;
revoke all on function public.is_household_member(uuid) from public,anon;
grant execute on function public.is_household_member(uuid) to authenticated;
create or replace function public.add_household_owner()
returns trigger language plpgsql security definer set search_path = ''
as $$begin insert into public.household_members(household_id,user_id,role) values(new.id,new.created_by,'owner');return new;end$$;
drop trigger if exists household_owner_trigger on public.households;
create trigger household_owner_trigger after insert on public.households for each row execute function public.add_household_owner();
alter table public.households enable row level security;
alter table public.household_members enable row level security;
alter table public.products enable row level security;
alter table public.inventory enable row level security;
alter table public.simulations enable row level security;
revoke all on public.households,public.household_members,public.products,public.inventory,public.simulations from anon,authenticated;
grant select,insert,update,delete on public.households,public.inventory,public.simulations to authenticated;
grant select on public.household_members,public.products to authenticated;
create policy "household select" on public.households for select to authenticated using(public.is_household_member(id));
create policy "household insert" on public.households for insert to authenticated with check(created_by=(select auth.uid()));
create policy "household update" on public.households for update to authenticated using(public.is_household_member(id)) with check(public.is_household_member(id));
create policy "household delete" on public.households for delete to authenticated using(created_by=(select auth.uid()));
create policy "members select" on public.household_members for select to authenticated using(public.is_household_member(household_id));
create policy "products select" on public.products for select to authenticated using(true);
create policy "inventory select" on public.inventory for select to authenticated using(public.is_household_member(household_id));
create policy "inventory insert" on public.inventory for insert to authenticated with check(public.is_household_member(household_id));
create policy "inventory update" on public.inventory for update to authenticated using(public.is_household_member(household_id)) with check(public.is_household_member(household_id));
create policy "inventory delete" on public.inventory for delete to authenticated using(public.is_household_member(household_id));
create policy "simulations select" on public.simulations for select to authenticated using(public.is_household_member(household_id));
create policy "simulations insert" on public.simulations for insert to authenticated with check(public.is_household_member(household_id));
create policy "simulations update" on public.simulations for update to authenticated using(public.is_household_member(household_id)) with check(public.is_household_member(household_id));
create policy "simulations delete" on public.simulations for delete to authenticated using(public.is_household_member(household_id));
