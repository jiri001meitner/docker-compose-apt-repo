# Jen poslední verze: `snapshot merge -latest`

- `aptly mirror create/update` nemá volbu „jen nejnovější verze“; `-filter`
  umí jen pevné podmínky (`caddy (>= 2.11)`). Zrcadlo proto stáhne vše, co
  upstream v `Packages` uvádí (Caddy `any-version` ~41 verzí, ~600 MB).
- `aptly snapshot merge -latest <cíl> <zdroj>` s jediným zdrojem ponechá
  nejnovější verzi každého balíčku (ověřeno: z `aaa` 1.0/1.1/2.0 zůstane 2.0).
- Zdrojový snapshot nejde smazat, dokud existuje snapshot z něj sloučený
  („won't delete snapshot that was used as source“), a `-force` nepomůže:
  `snapshot show` sloučeného snapshotu pak končí „snapshot with uuid … not
  found“. repo-sync proto drží pár `<x>` + `<x>-src` a maže ho společně
  (`Syncer._drop_with_source`); místo to nestojí, soubory drží zrcadlo.
