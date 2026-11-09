# Vendored Sigma conformance cases

These cases are copied unchanged from ZAAFElegia's language-neutral Sigma 2.1
conformance suite:

- Source: https://github.com/rifqifitriady/ZAAFElegia, directory `conformance/cases/`
- Commit: `66db1737691b1a4bd954afb3686840a60eb478f2` (8 Nov 2026)
- Copyright 2026 Rifqi Fitriady and ZAAFElegia contributors
- License: Apache License 2.0, copied in `LICENSE` next to this file; ZAAFElegia's
  `NOTICE` is copied unchanged as `NOTICE`

Only the cases that exercise a feature `zaafvesper sigma convert` supports, or a
rule it must refuse, are vendored. `pkg/sigma/conformance_test.go` runs them:
every rule is converted with a test field mapping (`Field` becomes
`evt.arg[Field]`), every event line becomes a ZAAFVesper event, and the rules
that match must be exactly the expected ones. Rules that need a feature the
converter refuses are listed in the test with the reason, and events that
ZAAFVesper cannot represent (JSON null, arrays, nested objects) are skipped and
counted; see the test for the list.
