# AGENTS.md

Hlavní a jediný závazný zdroj pravidel pro AI agenty a vývojáře v repozitáři
**docker-compose-apt-repo** (token-chráněné zrcadlo APT repozitářů).

Soubory `CLAUDE.md`, `COPILOT.md` a `GEMINI.md` jsou pouze symlinky na tento
soubor. `README.md`, `ARCHITECTURE.md`, `SECURITY.md`, `knowledge/` a
`skills/` jsou doplňková dokumentace bez vlastní normativní síly; při rozporu
platí tento soubor.

**Než začneš pracovat, projdi `skills/INDEX.md`** a odpovídá-li zadání
některému skillu, načti jeho `SKILL.md` dřív, než začneš měnit soubory.
Provozní fakta hledej přes `rg <téma> knowledge/` (načti jen trefené
soubory).

---

## 1. Komunikace

- Česky, stručně, technicky přesně. Nejistotu výslovně označ, nehádej.
- Kód, komentáře v kódu, `README.md`, `ARCHITECTURE.md` a commit zprávy jsou
  anglicky; tento soubor,
  `SECURITY.md`, `knowledge/` a `skills/` česky.

## 2. Ověřování

- Práce je hotová, až když prošly **všechny** kontroly z kapitoly 4 a
  změněná část je ověřená v cílovém prostředí (image, kontejner), ne jen na
  hostiteli.
- Změna Dockerfile, compose, `repo_*` nebo testů: sestav image a spusť
  integrační a e2e test (`README.md`, oddíl *Development and tests*).
- Změna jen dokumentace (`*.md`, `knowledge/`, `skills/`): kontrola obsahu,
  odkazů a diffu; build ani testy aplikace nespouštěj.
- Co ověřit nešlo, uveď i s důvodem. Varování se opravují, nikdy nepotlačují.

## 3. Kód

- Python 3, jen standardní knihovna (žádné balíčky v image), typovaný kód.
- **Modulárnost**: jeden modul = jedna odpovědnost; kód sdílený službami je
  v `repo_common/` a kopíruje se do obou image. Žádná duplicita mezi
  `repo_auth` a `repo_sync`.
- Externí programy se spouštějí jen přes `repo_common.proc` (absolutní cesta,
  seznam argumentů, nikdy shell).
- Žádné natvrdo zapsané provozní hodnoty: proměnné prostředí (`.env.example`),
  `config/mirrors.json`.
- Bash: `#!/usr/bin/env bash`, `set -Eeuo pipefail`, `local` ve funkcích,
  shellcheck čistý.
- Image se nepinují (plovoucí tagy, `build --pull`).

## 4. Povinné kontroly (lokálně i v CI)

```bash
pylint $(git ls-files '*.py')          # 10.00/10, všechny soubory včetně testů
ruff check . && ruff format --check .
mypy                                    # strict
python -m pytest -q
shellcheck $(git ls-files '*.sh') .githooks/pre-commit
```

- **pylint 10/10 bez obcházení**: zakázané jsou `# pylint: disable`,
  `disable=` a zmírněné limity v konfiguraci i vyřazení souborů. Hlášení se
  řeší v kódu (refaktoring, docstring, sdílený modul).
- Stejně tak bez `type: ignore` a bez nových `noqa` nebo `ignore` v ruffu.
  Jediné schválené výjimky jsou zapsané v `knowledge/linter-vyjimky.md`;
  novou smí schválit jen uživatel.

## 4.1 CI

- Workflowy v `.github/workflows/` (shellcheck, Python, compose, integrační
  test, e2e, pylint, security). Po **každém** pushi sleduj běh do konce
  (`gh run list`, `gh run watch <id> --exit-status`) a selhání oprav.

## 5. Tajemství a citlivé údaje

- Do repozitáře nepatří `.env`, `config/mirrors.json`, klíče (`config/keys/`),
  databáze, sockety ani cache. Hlídá to `.gitignore`, hook
  `.githooks/pre-commit` (zapni v každém klonu:
  `git config core.hooksPath .githooks`) a workflow `07_security.yml`
  (gitleaks nad celou historií, zakázané soubory přes
  `scripts/forbidden_files.sh`).
- Tokeny klientů se nikdy nevypisují do logů ani do výstupu agenta. Výstup
  `repo-admin token add|rotate|sync` obsahuje tajemství.
- Testovací data jsou umělá; skutečné tokeny, klíče a adresy zákazníků do
  testů ani `knowledge/` nepatří.
- Zranitelnosti se hlásí neveřejně podle `SECURITY.md`.

## 6. Dokumentace

- Změna chování, konfigurace nebo rozhraní → `README.md`; změna struktury
  nebo bezpečnostní hranice → `ARCHITECTURE.md`; nová proměnná →
  `.env.example` a `.env.ci`.
- Netriviální fakt → `knowledge/` (jeden fakt = jeden soubor + řádek
  v `knowledge/INDEX.md`). Opakovaný postup → `skills/<nazev>/SKILL.md`
  + řádek v `skills/INDEX.md`.

## 7. Nasazení

- Nasazuje role `apt_repo` v repozitáři `linuxadm`, vždy z commitu, který je
  pushnutý do `main` a má zelené CI.
