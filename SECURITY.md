# Bezpečnost projektu docker-compose-apt-repo

Repozitář obsahuje službu pro token-chráněné zrcadlo APT repozitářů
(`repo-auth`, `repo-admin`, `repo-sync`). Tento dokument určuje způsob
hlášení zranitelností. Bezpečnostní model popisuje
[ARCHITECTURE.md](ARCHITECTURE.md).

## Hlášení zranitelností

**Dosud nezveřejněné zranitelnosti a podezření na únik tajemství nehlas přes
veřejné issues, pull requesty, komentáře, diskuse ani commity.** Také návrh
opravy může prozradit způsob zneužití; nejprve ho projednej neveřejně.

Piš neveřejně správci projektu e-mailem na `podpora@itislove.cz`. Je-li
repozitář veřejný a má zapnuté *Private vulnerability reporting*, můžeš
použít i formulář *Report a vulnerability* na záložce *Security*.

- Citlivé podklady posílej až po dohodnutí vhodného zabezpečeného kanálu.
  Skutečné tokeny, hesla a privátní klíče neposílej ani do soukromého
  hlášení.

Do neveřejného hlášení uveď:

- dotčenou službu (`repo-auth`, `repo-admin`, `repo-sync`, Caddy snippet)
  a commit,
- popis problému, potřebná oprávnění a podmínky zneužití (např. platný
  token jiného zákazníka, přístup k socketu),
- reprodukční postup s umělými daty a očekávané versus skutečné chování,
- předpokládaný dopad a případný návrh opravy.

Přikládej pouze nezbytné výpisy bez tajemství a osobních údajů. U tokenů
nepřikládej ani jejich otisky; pro identifikaci stačí login.

## Opravy a zveřejnění

Opravy se připravují pro větev `main`, neveřejně (v dočasném soukromém
forku bezpečnostního advisory nebo mimo GitHub), ne veřejným pull
requestem. Údržba starších commitů není přislíbena.

Se správcem domluv termín zveřejnění podrobností. Před zveřejněním opravy
se podle potřeby omezí přístup, vymění kompromitované tokeny nebo podpisový
klíč a opraví nasazení. Po koordinovaném zveřejnění lze veřejně odkazovat na
oznámení a opravu. Tato politika nepřislibuje lhůtu vyřízení ani finanční
odměnu.
