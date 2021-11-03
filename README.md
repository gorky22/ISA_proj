# ISA_proj

jednoduchy program pre posielanie suboru cez skryty kanal cez icmp packet
Program je napísaný v jazyku C. 
Pre jeho správnu funkčnost sa musí spúštať s príkazom sudo.
skript sa dá preložit s príkazom make.
samotné spustenie: v korenovom adresary pomocou príkazu ./secret  [-l] [-s adresa -r meno suboru] [ -v ]
poznamka: poradie argumentov je volitelne
argumenty: 
[-v] urcene pre vypysi, ako je spusteny tento argument ta sa do terminalu vypisuje stav ako napr: server naslucha atd.
[-l] urceny pre spustenie skriptu v mode server moze by spusteny s prikazom [-v]
[-s adresa -r subor] tieto dva argumenty musia by spustene vzdy spolu a taktiez mozu byt spustene s prikazom [-v]