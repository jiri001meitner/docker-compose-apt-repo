---
name: novy-zakaznik
description: Založení zákazníka (účtu) a tokenu v repo-admin, prodloužení, blokace, rotace nebo zrušení tokenu. Použij při každé správě přístupu k repozitáři, i když jde o vlastní stroje (`account ensure`, `token sync`).
---

# Správa zákazníků a tokenů

Token je tajemství: vypisuje se jen jednou a **nesmí** se dostat do logu,
ticketu, chatu ani do výstupu agenta. V Ansible vždy `no_log: true`.

1. Účet s rozsahem a koncem předplatného:
   ```bash
   docker compose run --rm -T repo-admin account add acme --name "ACME s.r.o." \
     --email it@acme.example --scope /caddy --valid-until 2027-12-31
   ```
2. Token pro jeden stroj zákazníka (vypíše `login token` jednou):
   ```bash
   docker compose run --rm -T repo-admin token add acme --login acme-web1 --label web1
   ```
   Předej zákazníkovi zabezpečeným kanálem spolu s návodem z katalogu
   (`/` na webu repozitáře).
3. Údržba: `account extend --days N` (od pozdějšího z dneška a konce),
   `account block|unblock`, `token rotate|revoke`.
4. Ověř účinek bez restartu: `repo-admin token list`; repo-auth načte nový
   export při dalším požadavku, `docker compose ps` musí ukazovat *healthy*.

Vlastní stroje spravuje linuxadm idempotentně (`account ensure`,
`token sync` se stdin `{login: token}`), výstup `OK`/`CHANGED`.
