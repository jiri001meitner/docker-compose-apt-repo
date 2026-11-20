---
name: pridani-zrcadla
description: Přidání, změna nebo odebrání zrcadleného APT repozitáře (PPA, Cloudsmith, vlastní upstream) v `config/mirrors.json`. Použij, když se má zrcadlit nový repozitář, mění se architektury, filtr nebo prefix, nebo když `repo-sync report` hlásí „never synced“ či „No public key“.
---

# Přidání zrcadla

1. **Klíč upstreamu** získej z oficiálního zdroje (Launchpad API
   `signing_key_fingerprint`, dokumentace projektu) a ověř otisk proti
   druhému zdroji. U PPA stačí aktuální klíč z API; starý 1024bitový,
   kterým Launchpad podepisuje navíc, do keyringu **nepatří**
   (`knowledge/launchpad-dvoji-podpis-aptly-gpgv.md`). Ulož ho **armored** (`-----BEGIN PGP PUBLIC KEY BLOCK-----`,
   viz `knowledge/gpg-dearmor-binarni-vstup.md`). V produkci klíče spravuje
   role `apt_repo` v linuxadm (`roles/apt_repo/files/keys/`), sem se
   necommitují.
2. **Záznam v `config/mirrors.json`** podle `config/mirrors.json.example`:
   `name` (a-z0-9-), `prefix` (nesmí být vnořený do jiného ani rezervovaný),
   jedna `component`, `architectures`, `key_file` (absolutní cesta
   v kontejneru). U velkých repozitářů zvaž `filter`
   (např. `caddy (>= 2.11)`).
3. **Ověř konfiguraci a běh**:
   ```bash
   docker compose run --rm repo-sync sync
   docker compose run --rm repo-sync report   # zrcadlo bez „never synced“
   ```
4. **Přístup**: rozsah (`scope`) zákazníka je prefix; nové zrcadlo
   zpřístupni přes `repo-admin account set <id> --scope …`
   (viz [novy-zakaznik](../novy-zakaznik/SKILL.md)).

Změna `url`, `distribution`, `component`, `architectures` nebo `filter`
mirror znovu vytvoří; změna rozložení publikuje znovu
(`knowledge/aptly-publish-switch-layout.md`). Odebrané nebo přejmenované
zrcadlo se uklidí samo, až ho nic nepotřebuje.
