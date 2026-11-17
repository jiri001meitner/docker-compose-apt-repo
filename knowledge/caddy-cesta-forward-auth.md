# Caddy čistí cestu před forward_auth

- Caddy normalizuje cestu (`/caddy/../index.html` → `/index.html`) dřív, než
  vyhodnotí matchery a pošle `X-Forwarded-Uri` do `forward_auth`. Požadavek
  s tečkovými segmenty tak může skončit na veřejném katalogu (200), ne na
  repo-auth. e2e test to ověřuje („dot segments are cleaned onto the public
  catalogue“).
- Go (Caddy) odmítá neplatné procentové sekvence (`%zz`); repo-auth je
  odmítá také (`_BAD_ESCAPE`), aby se obě strany nikdy nelišily ve výkladu
  cesty.
- `%2F` dekóduje Caddy `file_server` stejně jako repo-auth, takže kontrola
  rozsahu sedí na skutečně servírovaný soubor.
