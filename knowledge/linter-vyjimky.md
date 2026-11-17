# Výjimky z linterů

Jediné výjimky z kontrol kódu v tomto repozitáři. Pylint žádnou nemá
(10/10 bez `disable`). Každá další výjimka potřebuje souhlas uživatele.

| Kde | Pravidlo | Proč nejde opravit v kódu | Stav |
|---|---|---|---|
| `repo_common/proc.py`, jediné volání `subprocess.run` | ruff `S603` | Pravidlo hlásí *každé* volání `subprocess` s neliterálními argumenty (cesta ke klíči, název snapshotu) a ruff nepozná, že vstup je ověřený. Riziko, které hlídá, řeší kód: absolutní cesta programu, seznam argumentů, žádný shell. Všechna volání programů jdou přes tuto jednu funkci. | čeká na schválení uživatelem |
| `pyproject.toml`, `pep8-naming.extend-ignore-names` | ruff `N815` pro `do_GET`, `do_HEAD` | Názvy předepisuje `http.server` (`do_<METODA>`); jiný název server nezavolá. Pylint je jako atributy třídy přijímá. | čeká na schválení uživatelem |

Ověření: `git grep -nE 'noqa|type: *ignore|pylint: *disable' -- '*.py'`
vrací jen řádek v `repo_common/proc.py`.
