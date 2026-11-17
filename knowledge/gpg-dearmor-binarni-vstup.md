# `gpg --dearmor` přijme i binární vstup

`gpg --dearmor` na binárním klíči (`.gpg`) skončí s kódem 0 a zapíše
nesmysl. Mirror pak selže až při `mirror update` s matoucím „No public key“.
`repo_sync.gpg.dearmor` proto nejdřív ověří hlavičku
`-----BEGIN PGP PUBLIC KEY BLOCK-----` a jinak skončí `ValueError`
(test `DearmorTest`). Klíče upstreamů v `config/keys/` musí být armored.
