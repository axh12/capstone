# Latest L1 acceptance results

Results directory: `l1-remaining-20261028/`.

- 145 named acceptance cases: 108 passed, 37 failed, no execution errors.
- Added 63 cases to the preserved original 82: 49 passed, 14 failed.
- 118-case security matrix: TN 37, FP 4, FN 24, TP 53.
- 27 fault/robustness checks: 18 passed, 9 failed; excluded from the matrix.
- Software regressions: 148 passed, 12 skipped, no failures.

See `l1-remaining-20261028/TEST-REPORT.md`, `report.json`,
`case-manifest.json`, `COVERAGE.md`, and `test-confusion-matrix.jpg`.
Physical equipment and installed pfSense/Snort enforcement were not tested.
Earlier reports are retained; their different case populations are not directly
comparable pass-rate benchmarks.
