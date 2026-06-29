# Sentinel Audit

Lokale netwerk-audit dashboard: scant openstaande poorten op infrastructuur die je zelf beheert, signaleert bekende risico's, en geeft niet-uitvoerbare hardening-suggesties. Alle resultaten zijn te exporteren als PDF-rapport en worden lokaal gelogd (SQLite).

## Wat dit wél is

- Een **portfolio-stuk**: laat zien dat je begrijpt hoe poort-scanning, risicoclassificatie en rapportage werken, end-to-end (Flask-backend, dashboard-frontend, PDF-export).
- Een **persoonlijk/intern audit-hulpmiddel** voor je eigen netwerk of dat van een klant die je expliciet hebt geautoriseerd.
- Een **basis voor een dienst**: jij voert de audit uit en levert het rapport, in plaats van de software als losstaand product te verkopen.

## Wat dit niet is

- **Geen vervanging voor Nessus/Qualys/OpenVAS** — die hebben duizenden CVE-checks, automatische updates en jarenlange validatie. Dit scant 25 bekende poorten.
- **Geen gecertificeerd product.** Overheidsinkoop in Nederland vereist doorgaans naleving van de BIO (Baseline Informatiebeveiliging Overheid), vaak een ISO 27001-gecertificeerde leverancier, en bij aanbestedingen een track record met referenties.
- **Geen aansprakelijkheids- of supportregeling.** Een overheid koopt geen securitytool van een leverancier zonder SLA en verzekering.

## Realistisch pad naar "verkocht aan de overheid"

Niet: dit script inpakken en een prijs erop plakken.

Wel:
1. Gebruik dit als bewijs van vaardigheid bij een sollicitatie (securitybedrijf, gemeente-IT, NCSC-traineeship).
2. Bied het aan als **dienst** (audit + rapport) aan een kleine organisatie die je kent — niet als product, maar als werk dat je levert.
3. Bouw via een bestaand bedrijf dat al op een overheids-inkooplijst staat, in plaats van zelf rechtstreeks te verkopen.

## Architectuur

- `app.py` — Flask-backend: poortscan (socket-based), risicoclassificatie, hardening-tekstsuggesties, PDF-rapportgeneratie (reportlab), SQLite-historie.
- `index.html` / `style.css` / `script.js` — dashboard met drie tabs: Audit, Hardening, History.

## Scope-afdwinging (server-side, niet alleen UI)

- Standaard target: `127.0.0.1`.
- Elk ander doelwit vereist een expliciete consent-vlag.
- Zelfs met consent: alleen loopback of RFC1918-privéadressen (`192.168.x.x`, `10.x.x.x`, `172.16-31.x.x`) worden geaccepteerd. Publieke IP's worden altijd geweigerd.

## Wat de tool bewust niet doet

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
