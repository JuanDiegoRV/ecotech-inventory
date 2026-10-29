create extension if not exists "pgcrypto";

do $$
begin
  create type public.rol_perfil as enum ('mentor', 'estudiante');
exception when duplicate_object then null;
end $$;

do $$
begin
  create type public.estado_sesion as enum ('pendiente', 'confirmada', 'cancelada', 'completada');
exception when duplicate_object then null;
end $$;

create table if not exists public.perfiles (
  id uuid primary key references auth.users(id) on delete cascade,
  nombre text not null check (length(trim(nombre)) between 2 and 120),
  bio text,
  rol public.rol_perfil not null default 'estudiante'
);

create table if not exists public.sesiones (
  id uuid primary key default gen_random_uuid(),
  mentor_id uuid not null references public.perfiles(id) on delete cascade,
  estudiante_id uuid not null references public.perfiles(id) on delete cascade,
  fecha timestamptz not null default now(),
  estado public.estado_sesion not null default 'pendiente',
  constraint sesiones_participantes_diferentes check (mentor_id <> estudiante_id)
);

create table if not exists public.mensajes (
  id uuid primary key default gen_random_uuid(),
  sesion_id uuid not null references public.sesiones(id) on delete cascade,
  remitente_id uuid not null references public.perfiles(id) on delete cascade,
  contenido text not null check (length(trim(contenido)) between 1 and 5000)
);

create index if not exists sesiones_mentor_id_idx on public.sesiones (mentor_id);
create index if not exists sesiones_estudiante_id_idx on public.sesiones (estudiante_id);
create index if not exists sesiones_estado_idx on public.sesiones (estado);
create index if not exists mensajes_sesion_id_idx on public.mensajes (sesion_id);
create index if not exists mensajes_remitente_id_idx on public.mensajes (remitente_id);

drop policy if exists perfiles_select_propios on public.perfiles;
drop policy if exists perfiles_insert_propios on public.perfiles;
drop policy if exists perfiles_update_propios on public.perfiles;
drop policy if exists sesiones_select_participantes on public.sesiones;
drop policy if exists sesiones_insert_participantes on public.sesiones;
drop policy if exists sesiones_update_mentor on public.sesiones;
drop policy if exists sesiones_update_participantes on public.sesiones;
drop policy if exists sesiones_delete_mentor on public.sesiones;
drop policy if exists sesiones_delete_mentor_pendiente on public.sesiones;
drop policy if exists mensajes_select_participantes on public.mensajes;
drop policy if exists mensajes_select_propios on public.mensajes;
drop policy if exists mensajes_insert_participantes on public.mensajes;
drop policy if exists mensajes_update_remitente on public.mensajes;
drop policy if exists mensajes_delete_remitente on public.mensajes;

drop function if exists public.es_participante_sesion(uuid, uuid);

create or replace function public.crear_perfil_usuario()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare
  nombre_usuario text;
begin
  nombre_usuario := coalesce(
    nullif(left(trim(new.raw_user_meta_data ->> 'full_name'), 120), ''),
    nullif(left(trim(new.raw_user_meta_data ->> 'name'), 120), ''),
    'Usuario'
  );
  if length(nombre_usuario) < 2 then nombre_usuario := 'Usuario'; end if;

  insert into public.perfiles (id, nombre, rol)
  values (new.id, nombre_usuario, 'estudiante'::public.rol_perfil)
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists crear_perfil_usuario_trigger on auth.users;
create trigger crear_perfil_usuario_trigger
after insert on auth.users
for each row execute function public.crear_perfil_usuario();

insert into public.perfiles (id, nombre, rol)
select u.id, 'Usuario', 'estudiante'::public.rol_perfil
from auth.users u
on conflict (id) do nothing;

create or replace function public.asignar_rol_mentor(p_usuario_id uuid)
returns void
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare rol_actual public.rol_perfil;
begin
  if coalesce(auth.role(), '') <> 'service_role' then
    raise exception 'Solo service_role puede asignar el rol mentor';
  end if;

  select p.rol into rol_actual
  from public.perfiles p
  where p.id = p_usuario_id
  for update;

  if rol_actual is null then raise exception 'El perfil indicado no existe'; end if;
  if rol_actual = 'mentor'::public.rol_perfil then return; end if;
  if rol_actual <> 'estudiante'::public.rol_perfil then
    raise exception 'Rol actual no válido para promoción';
  end if;

  update public.perfiles
  set rol = 'mentor'::public.rol_perfil
  where id = p_usuario_id;
end;
$$;

create or replace function public.validar_roles_sesion()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, public
as $$
declare mentor_rol public.rol_perfil; estudiante_rol public.rol_perfil;
begin
  select p.rol into mentor_rol from public.perfiles p where p.id = new.mentor_id;
  select p.rol into estudiante_rol from public.perfiles p where p.id = new.estudiante_id;
  if mentor_rol is distinct from 'mentor'::public.rol_perfil then
    raise exception 'mentor_id debe pertenecer a un perfil mentor';
  end if;
  if estudiante_rol is distinct from 'estudiante'::public.rol_perfil then
    raise exception 'estudiante_id debe pertenecer a un perfil estudiante';
  end if;
  return new;
end;
$$;

drop trigger if exists validar_roles_sesion_trigger on public.sesiones;
create trigger validar_roles_sesion_trigger
before insert or update on public.sesiones
for each row execute function public.validar_roles_sesion();

create or replace function public.proteger_participantes_sesion()
returns trigger language plpgsql set search_path = pg_catalog, public as $$
begin
  if new.mentor_id <> old.mentor_id or new.estudiante_id <> old.estudiante_id then
    raise exception 'Los participantes de una sesión no pueden modificarse';
  end if;
  return new;
end;
$$;

drop trigger if exists proteger_participantes_sesion_trigger on public.sesiones;
create trigger proteger_participantes_sesion_trigger
before update on public.sesiones
for each row execute function public.proteger_participantes_sesion();

create or replace function public.validar_transicion_sesion()
returns trigger language plpgsql set search_path = pg_catalog, public as $$
begin
  if new.estado = old.estado then return new; end if;

  if old.estado = 'pendiente' and new.estado = 'confirmada' then
    if auth.uid() is distinct from old.mentor_id then
      raise exception 'Solo el mentor puede confirmar una sesión';
    end if;
  elsif old.estado in ('pendiente', 'confirmada') and new.estado = 'cancelada' then
    if auth.uid() is distinct from old.mentor_id
       and auth.uid() is distinct from old.estudiante_id then
      raise exception 'Solo los participantes pueden cancelar una sesión';
    end if;
  elsif old.estado = 'confirmada' and new.estado = 'completada' then
    if auth.uid() is distinct from old.mentor_id then
      raise exception 'Solo el mentor puede completar una sesión';
    end if;
  else
    raise exception 'Transición de estado no permitida';
  end if;
  return new;
end;
$$;

drop trigger if exists validar_transicion_sesion_trigger on public.sesiones;
create trigger validar_transicion_sesion_trigger
before update on public.sesiones
for each row execute function public.validar_transicion_sesion();

create or replace function public.es_participante_sesion(p_sesion_id uuid)
returns boolean
language sql stable security definer
set search_path = pg_catalog, public
as $$
  select exists (
    select 1 from public.sesiones s
    where s.id = p_sesion_id
      and auth.uid() is not null
      and (s.mentor_id = auth.uid() or s.estudiante_id = auth.uid())
  );
$$;

create or replace function public.validar_remitente_mensaje()
returns trigger
language plpgsql security definer
set search_path = pg_catalog, public
as $$
begin
  if tg_op = 'INSERT' then
    if auth.uid() is null then raise exception 'Se requiere autenticación'; end if;
    new.remitente_id := auth.uid();
  end if;

  if not exists (
    select 1 from public.sesiones s
    where s.id = new.sesion_id
      and (s.mentor_id = new.remitente_id or s.estudiante_id = new.remitente_id)
  ) then
    raise exception 'El remitente no participa en la sesión';
  end if;
  return new;
end;
$$;

drop trigger if exists validar_remitente_mensaje_trigger on public.mensajes;
create trigger validar_remitente_mensaje_trigger
before insert or update on public.mensajes
for each row execute function public.validar_remitente_mensaje();

create or replace function public.proteger_identidad_mensaje()
returns trigger language plpgsql set search_path = pg_catalog, public as $$
begin
  if new.sesion_id <> old.sesion_id or new.remitente_id <> old.remitente_id then
    raise exception 'La sesión y el remitente no pueden modificarse';
  end if;
  return new;
end;
$$;

drop trigger if exists proteger_identidad_mensaje_trigger on public.mensajes;
create trigger proteger_identidad_mensaje_trigger
before update on public.mensajes
for each row execute function public.proteger_identidad_mensaje();

alter table public.perfiles enable row level security;
alter table public.perfiles force row level security;
alter table public.sesiones enable row level security;
alter table public.sesiones force row level security;
alter table public.mensajes enable row level security;
alter table public.mensajes force row level security;

revoke all on public.perfiles from anon, authenticated;
grant select on public.perfiles to authenticated;
grant insert (id, nombre, bio) on public.perfiles to authenticated;
grant update (nombre, bio) on public.perfiles to authenticated;

revoke all on public.sesiones from anon, authenticated;
grant select on public.sesiones to authenticated;
grant insert (mentor_id, estudiante_id, fecha) on public.sesiones to authenticated;
grant update (estado) on public.sesiones to authenticated;
grant delete on public.sesiones to authenticated;

revoke all on public.mensajes from anon, authenticated;
grant select on public.mensajes to authenticated;
grant insert (sesion_id, contenido) on public.mensajes to authenticated;
grant update (contenido) on public.mensajes to authenticated;
grant delete on public.mensajes to authenticated;

create policy perfiles_select_propios on public.perfiles
for select to authenticated using (id = auth.uid());

create policy perfiles_insert_propios on public.perfiles
for insert to authenticated
with check (id = auth.uid() and rol = 'estudiante'::public.rol_perfil);

create policy perfiles_update_propios on public.perfiles
for update to authenticated
using (id = auth.uid()) with check (id = auth.uid());

create policy sesiones_select_participantes on public.sesiones
for select to authenticated
using (mentor_id = auth.uid() or estudiante_id = auth.uid());

create policy sesiones_insert_participantes on public.sesiones
for insert to authenticated
with check (mentor_id = auth.uid() or estudiante_id = auth.uid());

create policy sesiones_update_participantes on public.sesiones
for update to authenticated
using (mentor_id = auth.uid() or estudiante_id = auth.uid())
with check (mentor_id = auth.uid() or estudiante_id = auth.uid());

create policy sesiones_delete_mentor_pendiente on public.sesiones
for delete to authenticated
using (mentor_id = auth.uid() and estado = 'pendiente'::public.estado_sesion);

create policy mensajes_select_participantes on public.mensajes
for select to authenticated
using (public.es_participante_sesion(sesion_id));

create policy mensajes_insert_participantes on public.mensajes
for insert to authenticated
with check (public.es_participante_sesion(sesion_id) and remitente_id = auth.uid());

create policy mensajes_update_remitente on public.mensajes
for update to authenticated
using (remitente_id = auth.uid() and public.es_participante_sesion(sesion_id))
with check (remitente_id = auth.uid() and public.es_participante_sesion(sesion_id));

create policy mensajes_delete_remitente on public.mensajes
for delete to authenticated
using (remitente_id = auth.uid() and public.es_participante_sesion(sesion_id));

revoke execute on function public.es_participante_sesion(uuid)
from public, anon, service_role;
grant execute on function public.es_participante_sesion(uuid) to authenticated;

revoke execute on function public.asignar_rol_mentor(uuid)
from public, anon, authenticated;
grant execute on function public.asignar_rol_mentor(uuid) to service_role;

revoke execute on function public.crear_perfil_usuario() from public, anon, authenticated, service_role;
revoke execute on function public.validar_roles_sesion() from public, anon, authenticated, service_role;
revoke execute on function public.validar_remitente_mensaje() from public, anon, authenticated, service_role;
revoke execute on function public.proteger_participantes_sesion() from public, anon, authenticated, service_role;
revoke execute on function public.validar_transicion_sesion() from public, anon, authenticated, service_role;
revoke execute on function public.proteger_identidad_mensaje() from public, anon, authenticated, service_role;

alter function public.crear_perfil_usuario() owner to postgres;
alter function public.asignar_rol_mentor(uuid) owner to postgres;
alter function public.validar_roles_sesion() owner to postgres;
alter function public.validar_remitente_mensaje() owner to postgres;
alter function public.es_participante_sesion(uuid) owner to postgres;
