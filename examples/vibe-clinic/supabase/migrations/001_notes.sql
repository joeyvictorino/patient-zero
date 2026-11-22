create table patients (id uuid primary key, clinic_id uuid, full_name text, date_of_birth date);
create table visit_notes (id uuid primary key, patient_id uuid references patients, body text);

alter table patients enable row level security;
create policy "anyone" on patients for select using (true);
