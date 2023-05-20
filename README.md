# ZP projekat
Projekat iz Zaštite podataka za školsku 2022/2023. godinu od [Katarine Jocić](https://github.com/katarinajj) i [Luke Simića](https://kocka.tech). Suština projekta je implementacija [PGP](https://en.wikipedia.org/wiki/Pretty_Good_Privacy) funkcionalnosti za upravljanje ključevima (stvaranje, uvoženje, izvoženje), slanje poruka i primanje poruka (u ovom slučaju, poruke su samo datoteke), i sve to dostupno kroz grafički korisnički interfejs.

## Pokretanje
```console
$ git clone https://github.com/KockaAdmiralac/ZP.git
$ cd ZP
$ python -m venv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
$ python app/main.py
```
Svi podaci aplikacije čuvaju se unutar `keyring.db`.

## Razvijanje
Projekat koristi [Qt Designer](https://doc.qt.io/qt-6/qtdesigner-manual.html) za svoj grafički korisnički interfejs. Ukoliko menjate bilo koji od `*.ui` fajlova iz `gui` paketa, neophodno je regenerisati odgovarajuće Python fajlove pokretanjem `app/gui/generate.sh` skripte.
