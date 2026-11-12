-- ============================================================================
-- מערכת ביקורות רבנות אוגמ״ר 96 – מסד נתונים נפרד (Supabase)
-- להריץ פעם אחת, כקובץ שלם, ב-SQL Editor של פרויקט Supabase חדש (לא בפרויקט של rab96).
-- אפשר להריץ שוב בלי נזק – כל הפקודות בטוחות להרצה חוזרת.
-- ============================================================================

-- ---------- טבלאות ----------
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text, full_name text, role text,
  is_admin boolean not null default false,
  active boolean not null default false,
  rejected boolean not null default false,
  requested_at timestamptz not null default now()
);
create table if not exists public.audits (
  id text primary key, owner uuid not null references auth.users(id),
  unit text default '', status text default 'draft', data jsonb not null,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create table if not exists public.defects (
  id text primary key, audit_id text, unit text default '', status text default 'open', data jsonb not null,
  created_at timestamptz not null default now(), updated_at timestamptz not null default now()
);
create table if not exists public.audit_log (
  id bigserial primary key, at timestamptz not null default now(), actor uuid,
  entity text, action text, entity_id text
);
create index if not exists defects_audit_id_idx on public.defects(audit_id);
create index if not exists audits_owner_idx on public.audits(owner);

-- ---------- פונקציות בדיקת הרשאה ----------
-- SECURITY DEFINER עם search_path ריק ושמות מלאים, כדי שלא ניתן יהיה "להחליף" טבלאות או פונקציות.
create or replace function public.is_active() returns boolean
language sql stable security definer set search_path = '' as
$$ select coalesce((select p.active and not p.rejected from public.profiles p where p.id = auth.uid()), false) $$;

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = '' as
$$ select coalesce((select p.is_admin and p.active and not p.rejected from public.profiles p where p.id = auth.uid()), false) $$;

-- האם המשתמש הנוכחי רשאי לערוך את הביקורת (בעלים או מנהל, ורק אם מאושר)
create or replace function public.can_edit_audit(p_audit text) returns boolean
language sql stable security definer set search_path = '' as
$$ select public.is_active() and (
     public.is_admin()
     or exists (select 1 from public.audits a where a.id = p_audit and a.owner = auth.uid())) $$;

-- ---------- הרשמה: פרופיל חדש תמיד לא פעיל ולא מנהל ----------
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles(id, email, full_name, role, is_admin, active, rejected)
  values (new.id, new.email, left(coalesce(new.raw_user_meta_data->>'full_name', ''), 120), null, false, false, false)
  on conflict (id) do nothing;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- ---------- הגנות שינוי (טריגרים) ----------
-- ביקורות: אסור לשנות מזהה; רק מנהל רשאי לשנות בעלות
create or replace function public.audits_guard() returns trigger
language plpgsql set search_path = '' as $$
begin
  if new.id is distinct from old.id then
    raise exception 'אסור לשנות מספר ביקורת' using errcode = '42501';
  end if;
  if new.owner is distinct from old.owner and not public.is_admin() then
    raise exception 'אסור לשנות בעלות על ביקורת' using errcode = '42501';
  end if;
  new.created_at := old.created_at;
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists audits_guard on public.audits;
create trigger audits_guard before update on public.audits
  for each row execute function public.audits_guard();

-- ליקויים: אסור לשנות מזהה; רק מנהל רשאי להעביר ליקוי לביקורת אחרת
create or replace function public.defects_guard() returns trigger
language plpgsql set search_path = '' as $$
begin
  if new.id is distinct from old.id then
    raise exception 'אסור לשנות מספר ליקוי' using errcode = '42501';
  end if;
  if new.audit_id is distinct from old.audit_id and not public.is_admin() then
    raise exception 'אסור להעביר ליקוי לביקורת אחרת' using errcode = '42501';
  end if;
  new.created_at := old.created_at;
  new.updated_at := now();
  return new;
end $$;
drop trigger if exists defects_guard on public.defects;
create trigger defects_guard before update on public.defects
  for each row execute function public.defects_guard();

-- פרופילים: מזהה ודוא״ל לא ניתנים לשינוי; אי אפשר להסיר את המנהל הפעיל האחרון
create or replace function public.profiles_guard() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  new.id := old.id;
  new.email := old.email;
  new.requested_at := old.requested_at;
  if (old.is_admin and old.active and not old.rejected)
     and not (new.is_admin and new.active and not new.rejected)
     and not exists (select 1 from public.profiles p
                     where p.id <> old.id and p.is_admin and p.active and not p.rejected) then
    raise exception 'לא ניתן להסיר את מנהל המערכת הפעיל האחרון' using errcode = '42501';
  end if;
  return new;
end $$;
drop trigger if exists profiles_guard on public.profiles;
create trigger profiles_guard before update on public.profiles
  for each row execute function public.profiles_guard();

-- ---------- יומן פעולות ----------
create or replace function public.log_change() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.audit_log(actor, entity, action, entity_id)
  values (auth.uid(), tg_table_name, lower(tg_op),
          coalesce((case when tg_op = 'DELETE' then old.id else new.id end)::text, ''));
  return coalesce(new, old);
end $$;
drop trigger if exists log_audits on public.audits;
create trigger log_audits after insert or update or delete on public.audits
  for each row execute function public.log_change();
drop trigger if exists log_defects on public.defects;
create trigger log_defects after insert or update or delete on public.defects
  for each row execute function public.log_change();

-- ---------- בקשות הצטרפות ואישורן (מנהל בלבד) ----------
create or replace function public.pending_requests()
returns table(id uuid, email text, full_name text, rejected boolean, requested_at timestamptz, email_confirmed boolean)
language plpgsql stable security definer set search_path = '' as $$
begin
  if not public.is_admin() then
    raise exception 'not allowed' using errcode = '42501';
  end if;
  return query
    select p.id, p.email, p.full_name, p.rejected, p.requested_at, (u.email_confirmed_at is not null)
    from public.profiles p join auth.users u on u.id = p.id
    where not p.active
    order by p.requested_at desc;
end $$;

create or replace function public.approve_user(p_id uuid, p_role text, p_admin boolean) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_admin() then
    raise exception 'not allowed' using errcode = '42501';
  end if;
  if p_role is null or p_role not in ('רב האוגדה', 'נגד רבנות אוגדתי', 'משגיח כשרות', 'מנהל המערכת') then
    raise exception 'תפקיד לא תקין' using errcode = '22023';
  end if;
  update public.profiles
     set active = true, rejected = false, role = p_role, is_admin = coalesce(p_admin, false)
   where id = p_id;
end $$;

create or replace function public.reject_user(p_id uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_admin() then
    raise exception 'not allowed' using errcode = '42501';
  end if;
  if p_id = auth.uid() then
    raise exception 'לא ניתן לדחות את עצמך' using errcode = '42501';
  end if;
  update public.profiles set rejected = true, active = false, is_admin = false where id = p_id;
end $$;

-- ---------- הרשאות EXECUTE ----------
-- ב-Supabase פונקציות חדשות פתוחות כברירת מחדל ל-anon ו-authenticated – סוגרים הכול ופותחים רק את הנדרש.
revoke all on function public.is_active()                     from public, anon, authenticated;
revoke all on function public.is_admin()                      from public, anon, authenticated;
revoke all on function public.can_edit_audit(text)            from public, anon, authenticated;
revoke all on function public.pending_requests()              from public, anon, authenticated;
revoke all on function public.approve_user(uuid, text, boolean) from public, anon, authenticated;
revoke all on function public.reject_user(uuid)               from public, anon, authenticated;
revoke all on function public.handle_new_user()               from public, anon, authenticated;
revoke all on function public.audits_guard()                  from public, anon, authenticated;
revoke all on function public.defects_guard()                 from public, anon, authenticated;
revoke all on function public.profiles_guard()                from public, anon, authenticated;
revoke all on function public.log_change()                    from public, anon, authenticated;

grant execute on function public.is_active()                      to authenticated;
grant execute on function public.is_admin()                       to authenticated;
grant execute on function public.can_edit_audit(text)             to authenticated;
grant execute on function public.pending_requests()               to authenticated;
grant execute on function public.approve_user(uuid, text, boolean) to authenticated;
grant execute on function public.reject_user(uuid)                to authenticated;

-- ---------- הרשאות טבלאות ----------
-- משתמש לא מחובר (anon) לא מקבל גישה לשום טבלה.
revoke all on table public.profiles, public.audits, public.defects, public.audit_log from anon;
revoke all on sequence public.audit_log_id_seq from anon, authenticated;
revoke insert, update, delete, truncate on table public.audit_log from authenticated;
revoke insert, delete, truncate on table public.profiles from authenticated;
revoke truncate on table public.audits, public.defects from authenticated;

-- ---------- RLS ----------
alter table public.profiles  enable row level security;
alter table public.audits    enable row level security;
alter table public.defects   enable row level security;
alter table public.audit_log enable row level security;

-- פרופילים: משתמש לא מאושר רואה רק את עצמו; רק מנהל מעדכן; אין הוספה או מחיקה ישירה
drop policy if exists p_sel on public.profiles;
create policy p_sel on public.profiles for select to authenticated
  using (id = auth.uid() or public.is_active());
drop policy if exists p_upd on public.profiles;
create policy p_upd on public.profiles for update to authenticated
  using (public.is_admin()) with check (public.is_admin());

-- ביקורות: קריאה למאושרים; יצירה בשם עצמך (מנהל – גם בשם אחר, לשחזור גיבוי); עריכה לבעלים או מנהל; מחיקה למנהל
drop policy if exists a_sel on public.audits;
create policy a_sel on public.audits for select to authenticated
  using (public.is_active());
drop policy if exists a_ins on public.audits;
create policy a_ins on public.audits for insert to authenticated
  with check (public.is_active() and (owner = auth.uid() or public.is_admin()));
drop policy if exists a_upd on public.audits;
create policy a_upd on public.audits for update to authenticated
  using (public.is_active() and (owner = auth.uid() or public.is_admin()))
  with check (public.is_active() and (owner = auth.uid() or public.is_admin()));
drop policy if exists a_del on public.audits;
create policy a_del on public.audits for delete to authenticated
  using (public.is_admin());

-- ליקויים: קריאה למאושרים; יצירה ועריכה רק לבעל הביקורת או למנהל; מחיקה למנהל
drop policy if exists d_sel on public.defects;
create policy d_sel on public.defects for select to authenticated
  using (public.is_active());
drop policy if exists d_ins on public.defects;
create policy d_ins on public.defects for insert to authenticated
  with check (public.can_edit_audit(audit_id));
drop policy if exists d_upd on public.defects;
create policy d_upd on public.defects for update to authenticated
  using (public.can_edit_audit(audit_id)) with check (public.can_edit_audit(audit_id));
drop policy if exists d_del on public.defects;
create policy d_del on public.defects for delete to authenticated
  using (public.is_admin());

-- יומן: קריאה למנהל בלבד (נכתב רק דרך הטריגר)
drop policy if exists l_sel on public.audit_log;
create policy l_sel on public.audit_log for select to authenticated
  using (public.is_admin());

-- ---------- זמן אמת (בטוח להרצה חוזרת) ----------
do $$
declare t text;
begin
  if exists (select 1 from pg_publication where pubname = 'supabase_realtime') then
    foreach t in array array['audits', 'defects', 'profiles'] loop
      if not exists (select 1 from pg_publication_tables
                     where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = t) then
        execute format('alter publication supabase_realtime add table public.%I', t);
      end if;
    end loop;
  end if;
end $$;

-- ---------- אחסון תמונות וחתימות (פרטי) ----------
insert into storage.buckets(id, name, public, file_size_limit, allowed_mime_types)
values ('photos', 'photos', false, 10485760, array['image/jpeg', 'image/png'])
on conflict (id) do update set public = false;

drop policy if exists ogmar96_photos_select on storage.objects;
create policy ogmar96_photos_select on storage.objects for select to authenticated
  using (bucket_id = 'photos' and public.is_active());
drop policy if exists ogmar96_photos_insert on storage.objects;
create policy ogmar96_photos_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'photos' and public.is_active());
-- מחיקה: רק מי שהעלה את התמונה, או מנהל. אין עדכון/החלפה של קבצים קיימים.
drop policy if exists ogmar96_photos_delete on storage.objects;
create policy ogmar96_photos_delete on storage.objects for delete to authenticated
  using (bucket_id = 'photos' and public.is_active()
         and (owner_id = auth.uid()::text or public.is_admin()));

-- ============================================================================
-- אחרי ההרצה: הירשם באפליקציה ואשר את הדוא״ל, ואז הרץ בנפרד (עם הדוא״ל שלך):
-- update public.profiles set active=true, is_admin=true, role='מנהל המערכת' where email='YOUR@EMAIL';
-- ============================================================================
