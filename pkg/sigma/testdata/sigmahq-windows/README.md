# SigmaHQ originals for windows (unchanged)

The Sigma rules under `rules/windows/` are copied unchanged from
https://github.com/SigmaHQ/sigma at commit `53b90df66c5b6d1b9be6ba9289c56fe49dd74a73`,
keeping SigmaHQ's own paths. They are licensed under the Detection Rule License (DRL) 1.1,
copied in `LICENSE.Detection.Rules.md`; each file names its author.

They are the source of `rules/sigma/windows/`; `TestShippedSigmaWindowsLinuxRegenerate`
(`cmd/zaafvesper/sigma_winlin_test.go`) converts them and checks the shipped files match.
See `rules/sigma/NOTICE.md`.
