# Sentinel Audit

Lokale netwerk-audit dashboard: scant openstaande poorten op infrastructuur die je zelf beheert, signaleert bekende risico's, en geeft niet-uitvoerbare hardening-suggesties. Alle resultaten zijn te exporteren als PDF-rapport en worden lokaal gelogd (SQLite).

## Wat dit wél is

- Een **portfolio-stuk**: laat zien dat je begrijpt hoe poort-scanning, risicoclassificatie en rapportage werken, end-to-end (Flask-backend, dashboard-frontend, PDF-export).
- Een **persoonlijk/intern audit-hulpmiddel** voor je eigen netwerk of dat van een klant die je expliciet hebt geautoriseerd.
- Een **basis voor een dienst**: jij voert de audit uit en levert het rapport, in plaats van de software als losstaand product te verkopen.

## Wat dit niet is

- **Geen vervanging voor Nessus/Qualys/OpenVAS** — die hebben duizenden CVE-checks, automatische updates en jarenlange validatie. Dit scant 25 bekende poorten.

wat ga ik ermee doen:

1. Bied het aan als **dienst** (audit + rapport) aan een kleine organisatie die je kent — niet als product, maar als werk dat je levert.
2. Bouw via een bestaand bedrijf dat al op een overheids-inkooplijst staat, in plaats van zelf rechtstreeks te verkopen.

## Architectuur

- `app.py` — Flask-backend: poortscan (socket-based), risicoclassificatie, hardening-tekstsuggesties, PDF-rapportgeneratie (reportlab), SQLite-historie.
- `index.html` / `style.css` / `script.js` — dashboard met drie tabs: Audit, Hardening, History.

## Scope-afdwinging (server-side, niet alleen UI)

- Standaard target: `127.0.0.1`.
- **Privénetwerk** (`192.168.x.x`, `10.x.x.x`, `172.16-31.x.x`): vereist alleen een eenvoudige consent-bevestiging.
- **Publiek IP of domein**: vereist extra autorisatie — een verplichte eigenaarsverklaring (vrije tekst, bv. bedrijfsnaam/domein/KVK) plus een bevestigingsvlag. Beide worden vastgelegd in de SQLite-log en in het PDF-rapport, met tijdstempel.
- Hostnames/domeinnamen worden eerst herleid naar een IP-adres (DNS-resolving) voordat scope-classificatie plaatsvindt — je kunt dus niet per ongeluk een publiek doelwit als "privé" laten doorgaan door een domeinnaam te gebruiken.
- Alles wat niet voldoet aan deze eisen wordt server-side geweigerd (403), ongeacht wat de UI toestaat.

## Wat de tool bewust niet doet

- Geen scan van een publiek doelwit zonder vastgelegde, expliciete eigenaarsverklaring.
- Geen automatische uitvoering van hardening-commando's — alleen tekst om te kopiëren.
- Geen obfuscatie om scanners te ontwijken.
- Geen persistence- of self-healing-tegen-verwijdering-mechanismen.
- Geen anonimisering van het netwerkverkeer.

## Starten

```bash
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5000`.
