"""
Sentinel Audit — Local Network Security Audit Dashboard
=========================================================
Een transparant audit-/hardening-adviestool.

Ontwerpregels (bewust, niet toevallig):
  - Scant standaard alleen localhost (127.0.0.1).
  - Elk ander doelwit vereist een expliciete consent-vlag van de gebruiker
    EN wordt server-side afgedwongen (niet alleen client-side checkbox).
  - Voert NOOIT zelf hardening-commando's uit. Het genereert alleen
    kant-en-klare commando's die de gebruiker zelf, bewust, kopieert en
    uitvoert. Geen "auto-remediation", geen achtergrondprocessen.
  - Geen obfuscatie, geen persistence, geen anonimiseringslaag.
  - Elke scan wordt gelogd in een lokale SQLite-database (volledig inzichtelijk
    voor de gebruiker via het History-tabblad).
"""

import io
import ipaddress
import socket
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timezone

from flask import Flask, jsonify, request, send_file, send_from_directory
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)

app = Flask(__name__, static_folder=".", static_url_path="")

DB_PATH = "sentinel_audit.db"

# Curated lijst van veelgebruikte poorten + bekend risiconiveau.
# "info"   = normaal, geen actie nodig, alleen ter info
# "low"    = meestal prima als correct geconfigureerd (bv. SSH)
# "medium" = vaak onbedoeld open, controleren
# "high"   = cleartext / vaak zonder auth / zeer gevoelig
COMMON_PORTS = {
    21: ("FTP", "high", "Cleartext authenticatie en dataverkeer."),
    22: ("SSH", "low", "Veilig mits sterke auth (key-based) en up-to-date."),
    23: ("Telnet", "high", "Volledig cleartext — gebruik nooit op een netwerk."),
    25: ("SMTP", "medium", "Open relay risico indien verkeerd geconfigureerd."),
    53: ("DNS", "info", "Normaal voor DNS-resolvers."),
    80: ("HTTP", "medium", "Onversleuteld — overweeg HTTPS-redirect."),
    110: ("POP3", "high", "Cleartext mail-protocol."),
    111: ("RPCbind", "medium", "Vaak onnodig extern bereikbaar."),
    135: ("MS-RPC", "medium", "Windows RPC — vaak doelwit van scans."),
    139: ("NetBIOS", "medium", "Legacy Windows file sharing."),
    143: ("IMAP", "medium", "Gebruik IMAPS (993) in plaats hiervan."),
    443: ("HTTPS", "info", "Versleuteld — controleer certificaat/cipher suite apart."),
    445: ("SMB", "high", "Veelvoorkomend doelwit (bv. EternalBlue-achtige CVEs)."),
    993: ("IMAPS", "info", "Versleutelde IMAP — prima."),
    995: ("POP3S", "info", "Versleutelde POP3 — prima."),
    1433: ("MSSQL", "high", "Database-poort; nooit extern blootstellen."),
    1521: ("Oracle DB", "high", "Database-poort; nooit extern blootstellen."),
    3306: ("MySQL", "high", "Database-poort; nooit extern blootstellen."),
    3389: ("RDP", "high", "Veelgebruikt doelwit voor brute-force/ransomware."),
    5432: ("PostgreSQL", "high", "Database-poort; nooit extern blootstellen."),
    5900: ("VNC", "high", "Vaak zwakke/geen authenticatie."),
    6379: ("Redis", "high", "Staat standaard zonder authenticatie — berucht lek."),
    8080: ("HTTP-alt", "medium", "Vaak een dev-server die per ongeluk open staat."),
    8443: ("HTTPS-alt", "info", "Versleuteld alternatief beheerpaneel."),
    27017: ("MongoDB", "high", "Staat standaard zonder authenticatie — berucht lek."),
}

RISK_WEIGHT = {"info": 0, "low": 1, "medium": 2, "high": 3}

# Hardening-suggesties per platform. Pure tekst — wordt nooit uitgevoerd
# door deze applicatie. De gebruiker kopieert en voert dit zelf uit.
HARDENING_TEMPLATES = {
    "linux_ufw": "sudo ufw deny {port}/tcp   # blokkeer poort {port} ({service})",
    "linux_iptables": "sudo iptables -A INPUT -p tcp --dport {port} -j DROP",
    "windows_firewall": (
        'netsh advfirewall firewall add rule name="Block {service} {port}" '
        "dir=in action=block protocol=TCP localport={port}"
    ),
}


def init_db():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                target TEXT NOT NULL,
                mode TEXT NOT NULL,
                ports_scanned INTEGER NOT NULL,
                open_ports INTEGER NOT NULL,
                high_risk_count INTEGER NOT NULL,
                duration_ms INTEGER NOT NULL
            )
            """
        )
        conn.commit()


def is_loopback(target: str) -> bool:
    try:
        ip = ipaddress.ip_address(target)
        return ip.is_loopback
    except ValueError:
        return target.lower() in ("localhost",)


def is_private_or_loopback(target: str) -> bool:
    """Sta alleen loopback of RFC1918-privéadressen toe, zelfs met consent.
    Dit blijft een tool voor eigen infrastructuur, geen internet-scanner."""
    if target.lower() == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(target)
        return ip.is_loopback or ip.is_private
    except ValueError:
        return False


def grab_banner(sock: socket.socket) -> str:
    try:
        sock.settimeout(0.6)
        data = sock.recv(128)
        return data.decode(errors="replace").strip().replace("\r", " ").replace("\n", " ")[:120]
    except Exception:
        return ""


def scan_port(target: str, port: int, timeout: float = 0.5):
    try:
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result == 0:
                banner = grab_banner(sock)
                return True, banner
            return False, ""
    except socket.gaierror:
        return False, ""
    except Exception:
        return False, ""


@app.route("/")
def root():
    return send_from_directory(".", "index.html")


@app.route("/api/scan", methods=["POST"])
def api_scan():
    payload = request.get_json(force=True, silent=True) or {}
    target = (payload.get("target") or "127.0.0.1").strip()
    mode = payload.get("mode", "common")
    consent = bool(payload.get("consent", False))
    range_start = int(payload.get("range_start", 1) or 1)
    range_end = int(payload.get("range_end", 1024) or 1024)

    if not target:
        return jsonify({"error": "Geen doelwit opgegeven."}), 400

    # --- Server-side scope afdwingen, niet alleen client-side checkbox ---
    if not is_loopback(target):
        if not consent:
            return (
                jsonify(
                    {
                        "error": (
                            "Voor een doelwit anders dan localhost is expliciete "
                            "autorisatie vereist. Vink de bevestiging aan."
                        )
                    }
                ),
                403,
            )
        if not is_private_or_loopback(target):
            return (
                jsonify(
                    {
                        "error": (
                            "Dit doelwit valt buiten je eigen netwerk (geen loopback "
                            "of privé-IP-range). Deze tool scant uitsluitend "
                            "infrastructuur die je zelf beheert."
                        )
                    }
                ),
                403,
            )

    if mode == "range":
        if range_end < range_start:
            return jsonify({"error": "Ongeldig poortbereik."}), 400
        span = range_end - range_start + 1
        if span > 1024:
            return jsonify({"error": "Bereik te groot — maximaal 1024 poorten per scan."}), 400
        ports = list(range(range_start, range_end + 1))
    else:
        ports = sorted(COMMON_PORTS.keys())

    start = time.time()
    findings = []
    for port in ports:
        open_, banner = scan_port(target, port)
        if open_:
            service, risk, note = COMMON_PORTS.get(port, ("Onbekende service", "medium", "Niet in standaardlijst — handmatig controleren."))
            findings.append(
                {
                    "port": port,
                    "service": service,
                    "risk": risk,
                    "note": note,
                    "banner": banner,
                }
            )
    duration_ms = int((time.time() - start) * 1000)

    findings.sort(key=lambda f: -RISK_WEIGHT.get(f["risk"], 0))
    high_risk_count = sum(1 for f in findings if f["risk"] == "high")

    with closing(sqlite3.connect(DB_PATH)) as conn:
        conn.execute(
            "INSERT INTO scans (timestamp, target, mode, ports_scanned, open_ports, high_risk_count, duration_ms) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                datetime.now(timezone.utc).isoformat(),
                target,
                mode,
                len(ports),
                len(findings),
                high_risk_count,
                duration_ms,
            ),
        )
        conn.commit()

    return jsonify(
        {
            "target": target,
            "mode": mode,
            "ports_scanned": len(ports),
            "duration_ms": duration_ms,
            "findings": findings,
        }
    )


@app.route("/api/hardening", methods=["POST"])
def api_hardening():
    """Genereert kant-en-klare (niet-uitgevoerde) hardening-commando's voor
    de meegegeven findings. De gebruiker voert deze zelf uit."""
    payload = request.get_json(force=True, silent=True) or {}
    findings = payload.get("findings", [])

    suggestions = []
    for f in findings:
        port = f.get("port")
        service = f.get("service", "service")
        if not isinstance(port, int):
            continue
        suggestions.append(
            {
                "port": port,
                "service": service,
                "risk": f.get("risk", "medium"),
                "commands": {
                    "linux_ufw": HARDENING_TEMPLATES["linux_ufw"].format(port=port, service=service),
                    "linux_iptables": HARDENING_TEMPLATES["linux_iptables"].format(port=port, service=service),
                    "windows_firewall": HARDENING_TEMPLATES["windows_firewall"].format(port=port, service=service),
                },
            }
        )
    return jsonify({"suggestions": suggestions})


@app.route("/api/report", methods=["POST"])
def api_report():
    """Genereert een PDF-rapport van een scanresultaat. Puur weergave/export —
    voert niets uit en wijzigt niets op het doelsysteem."""
    payload = request.get_json(force=True, silent=True) or {}
    target = payload.get("target", "onbekend")
    mode = payload.get("mode", "common")
    ports_scanned = payload.get("ports_scanned", 0)
    duration_ms = payload.get("duration_ms", 0)
    findings = payload.get("findings", [])

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        topMargin=22 * mm,
        bottomMargin=18 * mm,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "SentinelTitle", parent=styles["Title"], textColor=colors.HexColor("#0d1426"), fontSize=20
    )
    meta_style = ParagraphStyle("SentinelMeta", parent=styles["Normal"], textColor=colors.HexColor("#444"))
    section_style = ParagraphStyle(
        "SentinelSection", parent=styles["Heading2"], textColor=colors.HexColor("#0d1426"), spaceBefore=14
    )
    disclaimer_style = ParagraphStyle(
        "SentinelDisclaimer", parent=styles["Normal"], textColor=colors.HexColor("#666"), fontSize=9, leading=12
    )

    risk_colors = {
        "high": colors.HexColor("#c0392b"),
        "medium": colors.HexColor("#b8860b"),
        "low": colors.HexColor("#1e8449"),
        "info": colors.HexColor("#2471a3"),
    }

    story = []
    story.append(Paragraph("Sentinel Audit — Scanrapport", title_style))
    story.append(Spacer(1, 4 * mm))
    story.append(
        Paragraph(
            f"Doelwit: <b>{target}</b> &nbsp;&nbsp;|&nbsp;&nbsp; Modus: {mode} &nbsp;&nbsp;|&nbsp;&nbsp; "
            f"Gegenereerd: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            meta_style,
        )
    )
    story.append(
        Paragraph(
            f"Poorten gescand: {ports_scanned} &nbsp;&nbsp;|&nbsp;&nbsp; Open poorten: {len(findings)} "
            f"&nbsp;&nbsp;|&nbsp;&nbsp; Scanduur: {duration_ms} ms",
            meta_style,
        )
    )
    story.append(Spacer(1, 8 * mm))

    story.append(Paragraph("Bevindingen", section_style))
    if not findings:
        story.append(Paragraph("Geen openstaande poorten gevonden binnen de gescande set.", styles["Normal"]))
    else:
        table_data = [["Poort", "Service", "Risico", "Toelichting"]]
        for f in findings:
            table_data.append(
                [
                    str(f.get("port", "")),
                    f.get("service", ""),
                    f.get("risk", "").upper(),
                    f.get("note", ""),
                ]
            )
        table = Table(table_data, colWidths=[18 * mm, 32 * mm, 22 * mm, 90 * mm])
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d1426")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f4f6f8")]),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]
        for i, f in enumerate(findings, start=1):
            c = risk_colors.get(f.get("risk"), colors.black)
            style_cmds.append(("TEXTCOLOR", (2, i), (2, i), c))
            style_cmds.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))
        table.setStyle(TableStyle(style_cmds))
        story.append(table)

    story.append(Spacer(1, 10 * mm))
    story.append(Paragraph("Scope en beperkingen", section_style))
    story.append(
        Paragraph(
            "Dit rapport is gegenereerd door Sentinel Audit, een lokale poort-auditingtool. "
            "De scan was beperkt tot een doelwit waarvoor de uitvoerder zelf beheer en autorisatie "
            "heeft (loopback of privé-IP-bereik). Dit rapport bevat geen automatisch uitgevoerde "
            "wijzigingen — eventuele hardening-suggesties zijn losse, door een beheerder handmatig "
            "uit te voeren commando's. Dit rapport vervangt geen formele, gecertificeerde "
            "penetratietest of audit volgens een erkend kader (zoals BIO/ISO 27001).",
            disclaimer_style,
        )
    )

    doc.build(story)
    buf.seek(0)
    filename = f"sentinel-audit-report-{target.replace('.', '-')}.pdf"
    return send_file(buf, mimetype="application/pdf", as_attachment=True, download_name=filename)


@app.route("/api/history", methods=["GET"])
def api_history():
    with closing(sqlite3.connect(DB_PATH)) as conn:
        rows = conn.execute(
            "SELECT timestamp, target, mode, ports_scanned, open_ports, high_risk_count, duration_ms "
            "FROM scans ORDER BY id DESC LIMIT 50"
        ).fetchall()
    history = [
        {
            "timestamp": r[0],
            "target": r[1],
            "mode": r[2],
            "ports_scanned": r[3],
            "open_ports": r[4],
            "high_risk_count": r[5],
            "duration_ms": r[6],
        }
        for r in rows
    ]
    return jsonify({"history": history})


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)
