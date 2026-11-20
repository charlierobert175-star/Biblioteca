-- Biblioteca Pública: leitores autorizados, administradores e pasta privada de PDFs.
-- Executar uma vez no SQL Editor do Supabase.

-- 1. Tabelas
create table if not exists public.admins (
  email text primary key
);

create table if not exists public.leitores (
  email      text primary key,
  nome       text,
  ativo      boolean not null default true,
  criado_em  timestamptz not null default now()
);

insert into public.admins (email) values ('charlierobert175@gmail.com')
  on conflict do nothing;

-- 2. Funções de verificação (security definer: leem as tabelas sem depender das regras RLS)
create or replace function public.e_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.admins
    where lower(email) = lower(coalesce(auth.jwt() ->> 'email', ''))
  );
$$;

create or replace function public.e_leitor()
returns boolean language sql stable security definer set search_path = public as $$
  select public.e_admin() or exists (
    select 1 from public.leitores
    where lower(email) = lower(coalesce(auth.jwt() ->> 'email', '')) and ativo
  );
$$;

grant execute on function public.e_admin()  to authenticated;
grant execute on function public.e_leitor() to authenticated;

-- 3. Regras de acesso às tabelas
alter table public.admins   enable row level security;
alter table public.leitores enable row level security;

drop policy if exists "admin ve a sua linha" on public.admins;
create policy "admin ve a sua linha" on public.admins
  for select to authenticated
  using (lower(email) = lower(coalesce(auth.jwt() ->> 'email', '')));

drop policy if exists "leitores: admin ou o proprio leem" on public.leitores;
create policy "leitores: admin ou o proprio leem" on public.leitores
  for select to authenticated
  using (public.e_admin() or lower(email) = lower(coalesce(auth.jwt() ->> 'email', '')));

drop policy if exists "leitores: so admin altera" on public.leitores;
create policy "leitores: so admin altera" on public.leitores
  for all to authenticated
  using (public.e_admin()) with check (public.e_admin());

-- 4. Pasta privada para os PDFs
insert into storage.buckets (id, name, public)
  values ('livros', 'livros', false)
  on conflict (id) do update set public = false;

drop policy if exists "livros: leitores leem" on storage.objects;
create policy "livros: leitores leem" on storage.objects
  for select to authenticated
  using (bucket_id = 'livros' and public.e_leitor());

drop policy if exists "livros: admin envia" on storage.objects;
create policy "livros: admin envia" on storage.objects
  for insert to authenticated
  with check (bucket_id = 'livros' and public.e_admin());

drop policy if exists "livros: admin altera" on storage.objects;
create policy "livros: admin altera" on storage.objects
  for update to authenticated
  using (bucket_id = 'livros' and public.e_admin());

drop policy if exists "livros: admin apaga" on storage.objects;
create policy "livros: admin apaga" on storage.objects
  for delete to authenticated
  using (bucket_id = 'livros' and public.e_admin());
