# Artifacts

Evidence from real runs, committed so it can be re-checked without rerunning
anything. These are generated files, not hand-written claims.

| File | What it proves |
|---|---|
| `soak/soak-50.json` / `.md` | 50 consecutive full loops, each on a fresh database: same finding/case/execution counts, same validated/detected numbers, same ECS stable hash and OCSF UID set, 9 API reads returning 200 every time, zero failures and zero drift. |
| `soak/pytest-50.json` / `.md` | The whole test suite executed 50 times in a row: 292 passed on every run. |

Regenerate:

```bash
python deploy/soak/soak.py --iterations 50
python deploy/soak/tests.py --iterations 50
```

Both scripts take `--iterations`, write to `artifacts/soak/`, and exit non-zero if
anything drifts or fails. The `soak` workflow (manual dispatch) runs exactly these
commands and uploads the directory as a GitHub Actions artifact.

Screenshots used by the README live in `../assets/` (`ui-overview.png` from the demo
dataset, `ui-lab.png` from the lab database).
