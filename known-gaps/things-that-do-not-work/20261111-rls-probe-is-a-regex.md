Severity: MEDIUM
Gap-Class: weak

# The rls probe reads SQL with regular expressions

It does not parse SQL. It misses tables created by dynamic SQL, by an ORM at runtime, or outside the migrations directory, and it cannot judge whether a policy's condition is correct, only whether it is `USING (true)`. It reads migrations, never the live database, so drift is invisible to it.

What would close this: a mode that queries `pg_class` and `pg_policies` on a real database.
