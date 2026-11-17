# Verze aptly podle Ubuntu

- `ubuntu:latest` ukazovalo při vývoji (11/2026) na 24.04 s aptly 1.5,
  kterému chybí potřebné volby `publish list -json`. Image proto staví na
  `ubuntu:26.04` (aptly 1.6.2); tag plove přes bodová vydání.
- aptly 1.6: `publish list -json` vrací `Prefix`, `Distribution`,
  `SourceKind`, `Sources[{Component, Name}]`, `Architectures`,
  `AcquireByHash`. Výstup může začínat textem před JSON
  (`repo_sync.aptly.Aptly._json` hledá první `[`/`{`).
- `mirror update` se na tichém serveru vzdá asi po minutě, velké PPA ale
  napoprvé stahuje hodiny; proto `UPDATE_TIMEOUT` 6 h.
