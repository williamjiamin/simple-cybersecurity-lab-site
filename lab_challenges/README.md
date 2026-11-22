# Offline defensive challenge format, version 1

The schema is the single source of truth for the challenge collection format. The accompanying collection contains five original defensive training scenarios for adults. All artifacts are plain text, have no executable instructions, make no network calls, and refer to no live accounts or targets.

## Integrator contract

- Parse `challenge_collection.schema.json` and `challenges.v1.json` from local files.
- Check the `schema_version` exactly and reject unknown required fields, duplicated identifiers, non-unique choice IDs, and invalid answer references. The included verifier implements these checks.
- Present `scenario.context`, every labelled artifact, and `scenario.question` in reading order.
- Render `assessment.choices` as a keyboard-navigable, single-select group, with the choice label as the accessible name. Grade by exact string equality to `correct_choice_id`.
- Show `rationale` after a correct selection and `incorrect_feedback` after an incorrect selection; keep assessment feedback readable to assistive technology.
- Do not interpret artifacts as markup, executable commands, remote addresses, or instructions to contact third parties.
- Do not persist user answers remotely. Any local progress store must be separately documented and opt-in.
- The integration flag `SCL_LABS_ENABLED` defaults ON. Only an explicit environment value `0` disables the new lab. When disabled, bypass this module entirely and preserve the existing runtime behavior without writing challenge state. This data package does not modify the native application or assert that an absent application has implemented the flag.

Run the offline checker from the site root:

```sh
python3 -m site_audit --site-root . --challenge-pack lab_challenges/challenges.v1.json
```

The `--site-root` argument also checks the publishing HTML. See `docs/AUDIT_RUNBOOK.md` for security-header evidence requirements.
