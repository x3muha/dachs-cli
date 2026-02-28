# MSR2 Block-Übersicht (Regler 5)

Diese Übersicht beschreibt die aktuell genutzten Blöcke im `dachs-cli`.

## Kernblöcke (wichtig)

- **20**: Anlagen-/Modul-Stammdaten (Seriennummer, Teilenummer, Inbetriebnahmedatum, Softwarestände)
- **22**: Betriebszähler und Hauptzähler (Betriebsstunden, Starts, elektrische/thermische Arbeit)
- **24**: Live-Messwerte Dachs (Status, Drehzahl, Temperaturen, Sollwerte, Aktoren)
- **26**: Elektrische Messwerte/UC (Spannung, Strom, Frequenz, Impedanz)
- **70**: Heizkreis-relevante Zustände/Werte
- **76**: Warmwasser-relevante Zustände/Werte

## Erweiterte / Historie / Serviceblöcke

- **18**: Ring-/Historienverwaltung
- **28, 30, 31, 32, 34, 36**: Historien/Status-/Spezialstrukturen
- **50, 52, 54, 56, 60, 62, 66**: Einstell-/Service-/Regelnahe Blöcke
- **80, 82**: Service-/Warnhistorie
- **84, 86**: Motorüberwachung 1 (MW1/MW2 Snapshot bei SC)
- **88, 90**: Motorüberwachung 2 (MW1/MW2 Snapshot bei SC)
- **92, 94**: Motorüberwachung 3 (MW1/MW2 Snapshot bei SC)
- **100, 102, 104, 110, 112, 114**: Wartung/Erweiterte Anlage-/Metadaten

## Hinweise

- Für stabile Vollscans hat sich ein Intervall von **3.5s pro Block** bewährt.
- Einige Felder sind zustandsabhängig (Motor aus/an) und können bei Stillstand `0` oder `n.a.` liefern.
- Reserve-Felder sind standardmäßig im CLI ausgeblendet (mit `--show-reserved` einblendbar).


## Schreibbarkeit

Wichtig: Die CLI nutzt aktuell primär **Read**. Unten ist gemeint, ob ein Block laut Source
mindestens ein Feld mit `<access ... write="...">` enthält.

- **RO** = nur lesbar
- **RW
(teilweise)** = enthält schreibbare Parameter (nicht alle Felder!)

### Kurzüberblick

- **RO:** 18, 26, 28, 30, 31, 32, 34, 36, 52, 54, 56, 80, 82, 84, 86, 88, 90, 92, 94
- **RW (teilweise):** 20, 22, 24, 50, 60, 62, 66, 70, 76, 100, 102, 104, 110, 112, 114

### Beispiele für RW-Blöcke

- **50 (Hka_Ew):** Hydraulik-/Programm-/Einstellparameter
- **60 (Waermef_Ew):** Heizkurven-/Freigabe-/Regelparameter
- **66 (Stromf_Ew):** Stromtarif-/Zeiteinstellungen
- **70 (Hk_Ew):** Heizkreisparameter
- **76 (Ww_Ew):** Warmwasser-/Legionellenparameter
- **110/112/114 (Adresse*):** Adress-/Kontaktdaten

### Hinweis zur Praxis

Ob ein Feld tatsächlich geschrieben werden kann, hängt zusätzlich von Reglerstand,
Berechtigung/Zugriffsweg und ggf. Safety-Checks ab. Die obige Liste ist eine
**Source-basierte Capability-Übersicht**, kein Garant für erfolgreichen Write im Feldbetrieb.
