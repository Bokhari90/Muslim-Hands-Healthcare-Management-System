-- Muslim Hands Healthcare Management System: FULL Supabase setup + users. Safe to run again.
-- SQL Editor > New query > paste all > Run

create table if not exists public.profiles(
  user_id uuid primary key references auth.users on delete cascade,
  emp_id text, full_name text,
  role text not null default 'viewer' check (role in ('admin','entry','viewer')));
alter table public.profiles add column if not exists email text;
alter table public.profiles add column if not exists facilities text[] not null default '{}';

create table if not exists public.records(
  id text primary key, kind text not null, data jsonb not null,
  updated_at timestamptz not null default now(), updated_by uuid default auth.uid());
create index if not exists records_updated_idx on public.records(updated_at);

create or replace function public.my_role() returns text language sql security definer stable set search_path=public
as $$ select role from profiles where user_id=auth.uid() $$;
create or replace function public.my_facs() returns text[] language sql security definer stable set search_path=public
as $$ select coalesce(facilities,'{}') from profiles where user_id=auth.uid() $$;

-- admin: everything. entry: OPD / prescriptions / stock of OWN facilities only. viewer: read-only.
create or replace function public.can_write(k text, d jsonb) returns boolean language sql security definer stable set search_path=public as $$
  select case public.my_role()
    when 'admin' then true
    when 'entry' then (k in ('opd','vis','stk','ver') and (d->>'fid') = any(public.my_facs()))
    else false end $$;
create or replace function public.can_read(k text, d jsonb) returns boolean language sql security definer stable set search_path=public as $$
  select coalesce(public.my_role()='admin',false) or k in ('fac','meds') or (d->>'fid') = any(public.my_facs()) $$;

create or replace function public.touch() returns trigger language plpgsql as $$
begin new.updated_at=now(); new.updated_by=auth.uid(); return new; end $$;
drop trigger if exists t_touch on public.records;
create trigger t_touch before insert or update on public.records for each row execute function public.touch();

create or replace function public.new_user() returns trigger language plpgsql security definer set search_path=public as $$
begin insert into profiles(user_id,email) values(new.id,new.email) on conflict do nothing; return new; end $$;
drop trigger if exists on_signup on auth.users;
create trigger on_signup after insert on auth.users for each row execute function public.new_user();
insert into public.profiles(user_id,email) select id,email from auth.users on conflict do nothing;
update public.profiles p set email=u.email from auth.users u where u.id=p.user_id and p.email is null;

alter table public.profiles enable row level security;
alter table public.records  enable row level security;
drop policy if exists p_sel on public.profiles; drop policy if exists p_upd on public.profiles;
drop policy if exists r_sel on public.records;  drop policy if exists r_ins on public.records; drop policy if exists r_upd on public.records;
create policy p_sel on public.profiles for select to authenticated using (user_id=auth.uid() or public.my_role()='admin');
create policy p_upd on public.profiles for update to authenticated using (user_id=auth.uid()) with check (user_id=auth.uid());
revoke update on public.profiles from authenticated;
grant update(emp_id,full_name) on public.profiles to authenticated;
create policy r_sel on public.records for select to authenticated using (public.can_read(kind,data));
create policy r_ins on public.records for insert to authenticated with check (public.can_write(kind,data));
create policy r_upd on public.records for update to authenticated using (public.can_write(kind,data)) with check (public.can_write(kind,data));

-- facility names/locations are public so the home screen can list facilities before sign-in
grant select on public.records to anon;
drop policy if exists r_sel_anon on public.records;
create policy r_sel_anon on public.records for select to anon using (kind='fac');

-- public QR verification: anyone scanning a code can read ONLY that one document's summary (no listing)
create or replace function public.verify_code(p_code text) returns jsonb language sql security definer stable set search_path=public as $$
  select data from records where kind='ver' and id=p_code $$;
revoke execute on function public.verify_code(text) from public;
grant execute on function public.verify_code(text) to anon, authenticated;

-- used by the Admin dashboard to set a user's role and facilities
create or replace function public.admin_set_user(p_user uuid, p_role text, p_facs text[]) returns void
language plpgsql security definer set search_path=public as $$
begin
  if public.my_role() is distinct from 'admin' then raise exception 'admin only'; end if;
  update profiles set role=p_role, facilities=coalesce(p_facs,'{}') where user_id=p_user;
end $$;
revoke execute on function public.admin_set_user(uuid,text,text[]) from public, anon;
grant  execute on function public.admin_set_user(uuid,text,text[]) to authenticated;


-- ================= PART 2: CREATE USERS AND ASSIGN ROLES =================
-- Contains passwords: do NOT upload this file to GitHub. Delete it after running.

do $$
declare r record; uid uuid;
begin
for r in select * from (values
  ('muhammad.kiani@pk.mhworldwide.org','MZD@123',   'entry', array['f4','f8']),          -- BHU Muzaffarabad, RCPD Muzaffarabad
  ('waseem.asif@pk.mhworldwide.org',    'KT@123',    'entry', array['f5','f9']),          -- BHU Ghamkotli, RCPD Kotli
  ('khawar.hayat@pk.mhworldwide.org',   'GK@123',    'entry', array['f1']),               -- BHU Gujar Khan
  ('shams.ur-rehman@pk.mhworldwide.org','WZD@123',   'entry', array['f7']),               -- RCPD Wazirabad
  ('danish.irfan@pk.mhworldwide.org',   'MHU-S@123', 'entry', array['f2']),               -- Mobile Health Unit - Sindh
  ('waqas.bokhari@pk.mhworldwide.org',  '@MHPK@123', 'admin', array['f1','f2','f3','f4','f5','f6','f7','f8','f9'])  -- Admin: all facilities incl. MHU Islamabad
) as t(email,pw,urole,facs) loop
  select id into uid from auth.users where lower(email)=r.email;
  if uid is null then
    uid := gen_random_uuid();
    insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at,
      raw_app_meta_data,raw_user_meta_data,created_at,updated_at,
      confirmation_token,recovery_token,email_change_token_new,email_change,email_change_token_current,phone_change,phone_change_token,reauthentication_token)
    values('00000000-0000-0000-0000-000000000000',uid,'authenticated','authenticated',r.email,crypt(r.pw,gen_salt('bf')),now(),
      '{"provider":"email","providers":["email"]}','{}',now(),now(),'','','','','','','','');
    insert into auth.identities(id,user_id,provider_id,identity_data,provider,last_sign_in_at,created_at,updated_at)
    values(gen_random_uuid(),uid,uid::text,jsonb_build_object('sub',uid::text,'email',r.email,'email_verified',true),'email',now(),now(),now());
  else
    update auth.users set encrypted_password=crypt(r.pw,gen_salt('bf')), email_confirmed_at=coalesce(email_confirmed_at,now()) where id=uid;
  end if;
  insert into public.profiles(user_id,email) values(uid,r.email) on conflict (user_id) do nothing;
  update public.profiles set role=r.urole, facilities=r.facs, email=r.email where user_id=uid;
end loop;
end $$;

-- CHECK: you should see 6 rows
select email, role, facilities from public.profiles order by role, email;

-- FALLBACK if the block above errors on auth.users: create the 6 users by hand
-- (Authentication > Users > Add user, tick Auto Confirm User), then run only the
-- role lines, for example:
-- update public.profiles set role='admin', facilities=array['f1','f2','f3','f4','f5','f6','f7','f8','f9'] where email='waqas.bokhari@pk.mhworldwide.org';
-- update public.profiles set role='entry', facilities=array['f4','f8'] where email='muhammad.kiani@pk.mhworldwide.org';
