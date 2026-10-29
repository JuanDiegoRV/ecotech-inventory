# ENTREGA_MENTORLINK

Proyecto Integrador: Infraestructura con Supabase e IA.
El repositorio contiene la implementación; este documento contiene lo necesario para evaluar la actividad sin abrirlo.

## 1. Prompt de IA

Actúa como arquitecto senior de PostgreSQL y Supabase. Diseña MentorLink con `perfiles`, `sesiones` y `mensajes`, UUID, FKs, restricciones, Auth, RLS con `auth.uid()`, permisos CRUD, mensajes solo para participantes, edición/borrado por remitente, rol mentor exclusivo de `service_role`, estados válidos, CLI, pruebas y guía Email/Password + Google OAuth. Evita recursividad RLS, suplantación y secretos. No modifiques el proyecto remoto.

## 2. SQL completo

SQL compacto y funcional para tablas, relaciones, triggers, permisos y RLS:

```sql
create extension if not exists "pgcrypto";
create type public.rol_perfil as enum ('mentor','estudiante');
create type public.estado_sesion as enum ('pendiente','confirmada','cancelada','completada');
create table public.perfiles(id uuid primary key references auth.users(id) on delete cascade,nombre text not null check(length(trim(nombre)) between 2 and 120),bio text,rol public.rol_perfil not null default 'estudiante');
create table public.sesiones(id uuid primary key default gen_random_uuid(),mentor_id uuid not null references public.perfiles(id) on delete cascade,estudiante_id uuid not null references public.perfiles(id) on delete cascade,fecha timestamptz not null default now(),estado public.estado_sesion not null default 'pendiente',check(mentor_id<>estudiante_id));
create table public.mensajes(id uuid primary key default gen_random_uuid(),sesion_id uuid not null references public.sesiones(id) on delete cascade,remitente_id uuid not null references public.perfiles(id) on delete cascade,contenido text not null check(length(trim(contenido)) between 1 and 5000));
create index on public.sesiones(mentor_id);create index on public.sesiones(estudiante_id);create index on public.mensajes(sesion_id);
create or replace function public.es_participante(p uuid) returns boolean language sql stable security definer set search_path=pg_catalog,public as $$select exists(select 1 from public.sesiones s where s.id=p and auth.uid() is not null and auth.uid() in(s.mentor_id,s.estudiante_id))$$;
create or replace function public.asignar_mentor(p uuid) returns void language plpgsql security definer set search_path=pg_catalog,public as $$begin if coalesce(auth.role(),'')<>'service_role' then raise exception 'Solo service_role puede asignar mentor';end if;update public.perfiles set rol='mentor' where id=p and rol='estudiante';if not found then raise exception 'Perfil inexistente o no elegible';end if;end$$;
create or replace function public.validar_sesion() returns trigger language plpgsql security definer set search_path=pg_catalog,public as $$declare mr public.rol_perfil;er public.rol_perfil;begin select rol into mr from public.perfiles where id=new.mentor_id;select rol into er from public.perfiles where id=new.estudiante_id;if mr<>'mentor' or er<>'estudiante' then raise exception 'Roles de sesión inválidos';end if;return new;end$$;
create trigger validar_sesion before insert or update on public.sesiones for each row execute function public.validar_sesion();
create or replace function public.validar_estado() returns trigger language plpgsql set search_path=pg_catalog,public as $$begin if new.estado=old.estado then return new;end if;if old.estado='pendiente' and new.estado='confirmada' and auth.uid() is distinct from old.mentor_id then raise exception 'Solo el mentor confirma';elsif old.estado in('pendiente','confirmada') and new.estado='cancelada' and auth.uid() is distinct from old.mentor_id and auth.uid() is distinct from old.estudiante_id then raise exception 'Solo participantes cancelan';elsif old.estado='confirmada' and new.estado='completada' and auth.uid() is distinct from old.mentor_id then raise exception 'Solo el mentor completa';elsif not(old.estado='pendiente' and new.estado in('confirmada','cancelada') or old.estado='confirmada' and new.estado in('cancelada','completada')) then raise exception 'Transición inválida';end if;return new;end$$;
create trigger validar_estado before update on public.sesiones for each row execute function public.validar_estado();
create or replace function public.validar_mensaje() returns trigger language plpgsql security definer set search_path=pg_catalog,public as $$begin if tg_op='INSERT' then if auth.uid() is null then raise exception 'Autenticación requerida';end if;new.remitente_id:=auth.uid();elsif new.sesion_id<>old.sesion_id or new.remitente_id<>old.remitente_id then raise exception 'Identidad del mensaje inmutable';end if;if not exists(select 1 from public.sesiones s where s.id=new.sesion_id and new.remitente_id in(s.mentor_id,s.estudiante_id)) then raise exception 'Remitente no participante';end if;return new;end$$;
create trigger validar_mensaje before insert or update on public.mensajes for each row execute function public.validar_mensaje();
alter table public.perfiles enable row level security;alter table public.perfiles force row level security;alter table public.sesiones enable row level security;alter table public.sesiones force row level security;alter table public.mensajes enable row level security;alter table public.mensajes force row level security;
revoke all on public.perfiles,public.sesiones,public.mensajes from anon,authenticated;
grant select on public.perfiles to authenticated;grant insert(id,nombre,bio) on public.perfiles to authenticated;grant update(nombre,bio) on public.perfiles to authenticated;
grant select on public.sesiones to authenticated;grant insert(mentor_id,estudiante_id,fecha) on public.sesiones to authenticated;grant update(estado) on public.sesiones to authenticated;grant delete on public.sesiones to authenticated;
grant select on public.mensajes to authenticated;grant insert(sesion_id,contenido) on public.mensajes to authenticated;grant update(contenido) on public.mensajes to authenticated;grant delete on public.mensajes to authenticated;
create policy perfil_propietario on public.perfiles for select to authenticated using(id=auth.uid());create policy perfil_creacion on public.perfiles for insert to authenticated with check(id=auth.uid() and rol='estudiante');create policy perfil_edicion on public.perfiles for update to authenticated using(id=auth.uid()) with check(id=auth.uid());
create policy sesion_lectura on public.sesiones for select to authenticated using(auth.uid() in(mentor_id,estudiante_id));create policy sesion_creacion on public.sesiones for insert to authenticated with check(auth.uid() in(mentor_id,estudiante_id));create policy sesion_estado on public.sesiones for update to authenticated using(auth.uid() in(mentor_id,estudiante_id)) with check(auth.uid() in(mentor_id,estudiante_id));create policy sesion_borrado on public.sesiones for delete to authenticated using(mentor_id=auth.uid() and estado='pendiente');
create policy mensaje_lectura on public.mensajes for select to authenticated using(public.es_participante(sesion_id));create policy mensaje_creacion on public.mensajes for insert to authenticated with check(public.es_participante(sesion_id) and remitente_id=auth.uid());create policy mensaje_edicion on public.mensajes for update to authenticated using(remitente_id=auth.uid() and public.es_participante(sesion_id)) with check(remitente_id=auth.uid() and public.es_participante(sesion_id));create policy mensaje_borrado on public.mensajes for delete to authenticated using(remitente_id=auth.uid() and public.es_participante(sesion_id));
revoke execute on function public.es_participante(uuid) from public,anon,service_role;grant execute on function public.es_participante(uuid) to authenticated;revoke execute on function public.asignar_mentor(uuid) from public,anon,authenticated;grant execute on function public.asignar_mentor(uuid) to service_role;
alter function public.es_participante(uuid) owner to postgres;alter function public.asignar_mentor(uuid) owner to postgres;alter function public.validar_sesion() owner to postgres;alter function public.validar_mensaje() owner to postgres;
```

La migración ejecutada está en `supabase/migrations/20261029202606_inicializar_mentorlink.sql`.

## 3. CLI y pruebas

```powershell
npx supabase --version
npx supabase init
npx supabase migration new inicializar_mentorlink
npx supabase start
npx supabase db lint
npx supabase db reset
npm run build
npm run lint
```

Resultados reales: CLI 2.122.0; Docker 29.8.0; migración aplicada localmente; `db lint` informó `No schema errors found`; `db reset`, build y lint terminaron correctamente. RLS quedó habilitado y forzado en las tres tablas; se verificaron FKs, cascadas, índices, políticas y funciones SECURITY DEFINER.

Pruebas con mentor, estudiante y usuario ajeno: el ajeno obtuvo cero sesiones y mensajes; el mentor leyó dos mensajes; el estudiante editó el suyo; editar el mensaje ajeno no modificó filas; mentor confirmó; estudiante canceló; cambiar el rol directamente y llamar el RPC administrativo desde estudiante devolvieron HTTP 403. Se ejecutó un `db reset` final para retirar usuarios temporales.

La migración se ejecutó y probó localmente. Google OAuth está documentado, pero no configurado. El proyecto remoto no fue modificado; no se ejecutó `supabase db push`.

## 4. Auth en tres pasos

1. Dashboard → Authentication → Providers: habilitar Email, confirmación y recuperación. En URL Configuration agregar `http://localhost:5173/auth/callback` y la URL exacta de producción.
2. Google Cloud Console: crear OAuth Web y registrar `https://<PROJECT_REF>.supabase.co/auth/v1/callback`; local: `http://127.0.0.1:54321/auth/v1/callback`. Activar Google en Supabase y guardar Client ID/Secret.
3. Registrar los `redirectTo` exactos. No publicar Client Secret ni `service_role`; mantenerlos en Supabase o backend seguro.

