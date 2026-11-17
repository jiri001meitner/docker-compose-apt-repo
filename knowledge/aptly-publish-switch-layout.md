# aptly `publish switch` zachovává původní rozložení

`aptly publish switch` vymění snapshot, ale ponechá architektury, komponentu
a volby (např. `-acquire-by-hash`) z původního `publish snapshot`. Změna
architektur nebo komponenty se proto projeví až po `publish drop`
a novém `publish snapshot` (krátký výpadek dané distribuce).

`repo_sync.sync._layout_matches` porovnává skutečné rozložení z
`aptly publish list -json` (`Sources[].Component`, `Architectures`,
`AcquireByHash`) s konfigurací a podle toho volí switch nebo nové publikování.
Pokryto testy `test_architecture_change_republishes`,
`test_publication_without_acquire_by_hash_is_redone` a integračním testem.
