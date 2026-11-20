# Launchpad podepisuje PPA dvěma klíči, aptly chce ověřit oba

- `InRelease` PPA na `ppa.launchpadcontent.net` je podepsaný **aktuálním**
  klíčem PPA (ten vrací Launchpad API `signing_key_fingerprint`, u starších
  PPA 4096bitové RSA) a navíc **starým 1024bitovým** klíčem PPA. Ověřeno
  2026-11-20 u mozillateam, libreoffice, ubuntuhandbook1/transmission,
  i2p-maintainers a longsleep/golang-backports; flatpak/stable má jen jeden
  podpis.
- `gpgv` při podpisu neznámým klíčem skončí kódem 2 (`NO_PUBKEY`), i když
  druhý podpis je platný. aptly 1.6 (`gpgProvider` `gpg2` i `internal`)
  bere každé selhání jako chybu: `verification of detached signature
  failed: exit status 2`, resp. `signature made by unknown entity`. Zrcadlo
  pak zůstane „never synced“.
- apt jeden platný podpis od klíče z keyringu stačí, neznámé podpisy
  ignoruje.
- Přidat starý 1024bitový klíč do keyringu **nelze**: gpgv by pak přijal
  i `InRelease` podepsaný jen jím, ověření by mělo sílu 1024bitového RSA.
- Řešení: `repo_sync/gpgv.py` jako `/usr/local/bin/gpgv` v image aptly
  (aptly hledá `gpgv` v `PATH`) s pravidlem apt. Klíč zrcadla je tedy jen
  aktuální klíč z Launchpad API.
- Pozor na přilepenou druhou zprávu: `InRelease` = platná zpráva se dvěma
  podpisy + za ní další clearsigned zpráva neznámým klíčem dá status
  `VALIDSIG`, `ERRSIG … 9`, `NO_PUBKEY` **a** `ERROR`, rc 2. Pravidlo proto
  povoluje jen výčet klíčových slov (`ALLOWED`) a cokoli jiného odmítne.
