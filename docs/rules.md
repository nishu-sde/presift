# What Presift reports

Presift reads the migration statement only — never your live schema, table size, MySQL version or
session variables. Findings are therefore **risks to review before you run the migration**, not
verdicts about your database. Every finding cites the MySQL 8.0 Reference Manual section it is
based on, so you can check the reasoning rather than trust the tool.

| Rule | Name | Default severity | What it is about |
|---|---|---|---|
| `MG001` | destructive-change | error | statements that remove data or objects and cannot be rolled back, because MySQL DDL is not transactional |
| `MG002` | blocking-or-rebuilding-alter | error / warning | `ALTER TABLE` operations that copy the table, rebuild it in place, or block concurrent writes — the statements behind metadata-lock pile-ups |
| `MG003` | missing-algorithm-lock-assertion | warning | an `ALTER TABLE` with an `MG002` finding that does not declare `ALGORITHM=` / `LOCK=`, so MySQL may silently fall back to a blocking copy instead of failing fast |
| `MG004` | add-column-position-not-instant | warning | adding a column at a specific position, which is instant only on recent MySQL and only under conditions your table may not meet |

Severity per rule is your choice: override it in `presift.toml`, or disable a rule entirely. Some
`MG002` findings carry a confidence marker where the outcome depends on the column's existing
definition, which Presift cannot see.

## Suppressing a finding you have decided is intentional

Annotate the statement:

```sql
-- presift: allow MG001 dropping the table replaced by orders_v2 in migration 0141
DROP TABLE orders_legacy;
```

The annotation is accepted on the preceding line, inside the statement, or as a trailing comment
after the semicolon, and a reason is expected so the next reviewer can see why. Suppressed findings
are hidden by default and shown with `--show-suppressed`.

## Ruleset updates

Rule coverage and precision are part of the subscription: an active key gets the newer releases,
including changes that follow MySQL's own behaviour as it changes. The `rules` input and
`presift.toml` let you adopt changes at your own pace.
