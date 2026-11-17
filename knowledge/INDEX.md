# Znalostní báze

Jeden fakt = jeden soubor. Hledej `rg <téma> knowledge/`, otevírej jen
trefené soubory. Postupy patří do `skills/`.

| Soubor | Fakt |
|---|---|
| [linter-vyjimky.md](linter-vyjimky.md) | jediné výjimky z linterů (ruff S603 v `repo_common/proc.py`, N815 pro `do_GET`/`do_HEAD`) a jejich stav schválení |
| [aptly-publish-switch-layout.md](aptly-publish-switch-layout.md) | `publish switch` zachovává architektury, komponentu a by-hash; změna = drop + publish |
| [aptly-verze-ubuntu.md](aptly-verze-ubuntu.md) | proč `ubuntu:26.04` (aptly 1.6), formát `publish list -json`, timeout `mirror update` |
| [gpg-dearmor-binarni-vstup.md](gpg-dearmor-binarni-vstup.md) | `gpg --dearmor` na binárním klíči uspěje a zapíše nesmysl |
| [caddy-cesta-forward-auth.md](caddy-cesta-forward-auth.md) | Caddy čistí cestu před forward_auth, `%zz` a `%2F` |
