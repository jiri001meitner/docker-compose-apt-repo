# Výjimky z linterů

Jediné výjimky z kontrol kódu v tomto repozitáři. Pylint žádnou nemá
(10/10 bez `disable`). Každá další výjimka potřebuje souhlas uživatele; CI (`06_pylint.yml`)
odmítne `noqa` kdekoli jinde.

| Kde | Pravidlo | Proč nejde opravit v kódu | Stav |
|---|---|---|---|
| `repo_common/proc.py`, jediné volání `subprocess.run` | ruff `S603` | Pravidlo hlásí *každé* volání `subprocess` s neliterálními argumenty (cesta ke klíči, název snapshotu) a ruff nepozná, že vstup je ověřený. Riziko, které hlídá, řeší kód: absolutní cesta programu, seznam argumentů, žádný shell. Všechna volání programů jdou přes tuto jednu funkci. | schváleno uživatelem 2026-11-17 |
| `pyproject.toml`, `pep8-naming.extend-ignore-names` | ruff `N815` pro `do_GET`, `do_HEAD` | Názvy předepisuje `http.server` (`do_<METODA>`); jiný název server nezavolá. Pylint je jako atributy třídy přijímá. | schváleno uživatelem 2026-11-17 |

Ověření: `git grep -nE 'noqa|type: *ignore|pylint: *disable' -- '*.py'`
vrací jen řádek v `repo_common/proc.py`.

## Gitleaks

| Kde | Nález | Proč to není tajemství | Stav |
|---|---|---|---|
| `.gitleaksignore`, commit `25b5406`, `config/mirrors.json.example:2` | `generic-api-key` | Ukázkový otisk (`0123…`) veřejného podpisového klíče. Od dalšího commitu je tam nehexový zástupný text, který gitleaks nehlásí a validace odmítne. | schváleno uživatelem 2026-11-17 |

Do `.gitleaksignore` patří jen prověřené falešné nálezy s odůvodněním zde.
Skutečné tajemství se nikdy neignoruje: vymění se (viz `skills/` v linuxadm,
`zakladani-repozitare`).
