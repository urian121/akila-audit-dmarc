"""Genera el PDF de descarga directa del reporte del checker (ReportLab: Python puro, sin dependencias de sistema)."""

import io
import os
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

# Logo de encabezado: se dibuja directamente sobre el canvas de cada página
# (onFirstPage/onLaterPages), no como flowable — así aparece en TODAS las
# páginas sin ocupar espacio del flujo de contenido.
_STATIC_IMG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "img")
_HEADER_IMG = ImageReader(os.path.join(_STATIC_IMG_DIR, "report_header.png"))
_HEADER_PX_W, _HEADER_PX_H = _HEADER_IMG.getSize()

HEADER_H = 40  # pt — el ancho se calcula preservando la proporción real del PNG.
HEADER_W = HEADER_H * _HEADER_PX_W / _HEADER_PX_H
TOP_MARGIN = 28 * mm   # deja hueco de sobra para el header (10mm de aire + HEADER_H + gap antes del contenido).
BOTTOM_MARGIN = 16 * mm


def _draw_page_furniture(canvas, doc):
    """Dibuja el logo arriba a la izquierda en cada página — registrado como onFirstPage/onLaterPages en SimpleDocTemplate."""
    page_w, page_h = LETTER
    canvas.saveState()
    canvas.drawImage(
        _HEADER_IMG, 16 * mm, page_h - 10 * mm - HEADER_H,
        width=HEADER_W, height=HEADER_H, mask="auto",
    )
    canvas.restoreState()

INK = colors.HexColor("#18181b")
MUTED = colors.HexColor("#52525b")
FAINT = colors.HexColor("#a1a1aa")
BORDER = colors.HexColor("#e4e4e7")
CARD_BG = colors.HexColor("#fafafa")
BRAND_BG = colors.HexColor("#fdf2f6")
BRAND_BORDER = colors.HexColor("#f9c3d3")

STATUS_COLORS = {
    "ok": colors.HexColor("#047857"),
    "warn": colors.HexColor("#b45309"),
    "fail": colors.HexColor("#be123c"),
    "na": colors.HexColor("#71717a"),
}
STATUS_LABELS = {"ok": "OK", "warn": "ADVERTENCIA", "fail": "FALLA", "na": "N/D"}
SEVERITY_COLORS = {"Alta": STATUS_COLORS["fail"], "Media": STATUS_COLORS["warn"], "Baja": STATUS_COLORS["na"]}

# Padding interno (pt) de cada caja de tarjeta (_boxed) a cada lado — cualquier
# tabla/párrafo anidado dentro de una caja debe dimensionarse contra
# (ancho de página - 2*CARD_PAD), no el ancho completo, o su contenido se
# recorta contra el borde derecho (ReportLab no encoge tablas anidadas solo).
CARD_PAD = 10

# Tope de remitentes mostrados por reporte en el PDF — ver comentario en
# _report_flowable() sobre por qué es necesario (LayoutError con reportes grandes).
MAX_REPORT_RECORDS = 30


def _styles():
    """Estilos de párrafo reusados en todo el documento (Helvetica/Courier, base-14: sin fuentes externas).

    ParagraphStyle no hereda 'leading' de fontSize (default fijo de 12pt) — hay
    que fijarlo a mano en cualquier estilo con fontSize > 10 o el texto de la
    línea siguiente se monta sobre los descendentes de la anterior.
    """
    return {
        "subtitle": ParagraphStyle("subtitle", fontName="Helvetica", fontSize=9, leading=12, textColor=MUTED),
        "h2": ParagraphStyle("h2", fontName="Helvetica-Bold", fontSize=9, leading=12, textColor=MUTED),
        "card_title": ParagraphStyle("card_title", fontName="Helvetica-Bold", fontSize=9.5, leading=12, textColor=INK),
        "help": ParagraphStyle("help", fontName="Helvetica-Oblique", fontSize=7.5, textColor=FAINT, spaceBefore=2, spaceAfter=4),
        "body": ParagraphStyle("body", fontName="Helvetica", fontSize=8.5, textColor=INK, leading=12, spaceAfter=3),
        "muted": ParagraphStyle("muted", fontName="Helvetica", fontSize=8, textColor=MUTED, leading=11, spaceAfter=3),
        "mono": ParagraphStyle("mono", fontName="Courier", fontSize=7, textColor=colors.HexColor("#3f3f46"), leading=10, backColor=colors.HexColor("#f4f4f5"), borderPadding=5, spaceBefore=2, spaceAfter=4),
        "summary": ParagraphStyle("summary", fontName="Helvetica", fontSize=9, textColor=INK, leading=13),
    }


def _status_style(status, base):
    """Variante de un estilo con el color del status (ok/warn/fail/na)."""
    return ParagraphStyle(f"{base.name}_{status}", parent=base, textColor=STATUS_COLORS.get(status, MUTED))


def _hex(color):
    """'#rrggbb' de un Color de reportlab, para usar en <font color="..."> dentro de un Paragraph."""
    return f"#{color.hexval()[2:]}"


def _badge(status, styles):
    """Badge de estado alineado a la derecha, mismo texto que el badge de la tarjeta HTML."""
    style = ParagraphStyle("badge", parent=styles["card_title"], fontSize=7.5, textColor=STATUS_COLORS.get(status, MUTED), alignment=TA_RIGHT)
    return Paragraph(STATUS_LABELS.get(status, "N/D"), style)


def _boxed(flowables, bg=CARD_BG, border=BORDER, width=None):
    """Envuelve una lista de flowables en una caja con borde fino y suave (equivalente a una 'card' del HTML)."""
    table = Table([[flowables]], colWidths=[width] if width else None)
    table.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.75, border),
        ("BACKGROUND", (0, 0), (-1, -1), bg),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return table


def _header_row(title, status, styles, width):
    """Fila de encabezado de tarjeta: título a la izquierda, badge de estado a la derecha."""
    row = Table([[Paragraph(escape(title), styles["card_title"]), _badge(status, styles)]], colWidths=[width * 0.7, width * 0.3])
    row.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    return row


def _bullets(items, style):
    """Lista de strings como párrafo con viñetas ('• ' por línea) — Paragraph no soporta <ul>/<li>."""
    if not items:
        return None
    text = "<br/>".join(f"• {escape(str(item))}" for item in items)
    return Paragraph(text, style)


def _kv_table(mapping, styles, width):
    """Tabla clave/valor de dos columnas (sin bordes), para kv/tags/policy_kv."""
    if not mapping:
        return None
    key_style = styles["muted"]
    val_style = styles["body"]
    rows = [[Paragraph(escape(str(k)), key_style), Paragraph(escape(str(v)), val_style)] for k, v in mapping.items()]
    table = Table(rows, colWidths=[width * 0.32, width * 0.68])
    table.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 1),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return table


def _card_content(card, styles, width):
    """Arma el contenido interno de una tarjeta según su 'kind' — refleja render_card() de check_result.html."""
    elements = []
    kind = card.get("kind")

    if card.get("help_text"):
        elements.append(Paragraph(escape(card["help_text"]), styles["help"]))

    if kind == "empty":
        elements.append(Paragraph("sin datos", styles["muted"]))

    elif kind == "error":
        elements.append(Paragraph(escape(card.get("message", "")), _status_style("fail", styles["body"])))

    elif kind == "text":
        elements.append(Paragraph(escape(card.get("text", "")), styles["body"]))

    elif kind == "dmarc":
        if card.get("has_record"):
            elements.append(Paragraph(f"Configurado — este dominio tiene {escape(card['title'])} publicado.", _status_style("ok", styles["body"])))
        else:
            elements.append(Paragraph(f"No configurado — este dominio NO tiene {escape(card['title'])} publicado.", _status_style("fail", styles["body"])))
            if card.get("message"):
                elements.append(Paragraph(escape(card["message"]), styles["muted"]))
        bullets = _bullets(card.get("explanations"), styles["body"])
        if bullets:
            elements.append(bullets)
        if card.get("record"):
            elements.append(Paragraph(escape(card["record"]), styles["mono"]))
        warn = _bullets(card.get("warnings"), _status_style("warn", styles["body"]))
        if warn:
            elements.append(warn)

    elif kind == "spf":
        if card.get("has_record"):
            elements.append(Paragraph("Configurado — este dominio tiene SPF publicado.", _status_style("ok", styles["body"])))
        else:
            elements.append(Paragraph("No configurado — este dominio NO tiene SPF publicado.", _status_style("fail", styles["body"])))
            if card.get("message"):
                elements.append(Paragraph(escape(card["message"]), styles["muted"]))
        mechanism_lines = []
        for m in card.get("mechanisms") or []:
            highlight = f'<font face="Courier"><b>{escape(m["value"])}</b></font>' if m.get("value") else ""
            mechanism_lines.append(f"• {escape(m.get('prefix', ''))}{highlight}{escape(m.get('suffix', ''))}")
        if mechanism_lines:
            elements.append(Paragraph("<br/>".join(mechanism_lines), styles["body"]))
        if card.get("all_explanation"):
            elements.append(Paragraph(escape(card["all_explanation"]), styles["body"]))
        if card.get("record"):
            elements.append(Paragraph(escape(card["record"]), styles["mono"]))
        warn = _bullets(card.get("warnings"), _status_style("warn", styles["body"]))
        if warn:
            elements.append(warn)

    elif kind == "record":
        if card.get("record"):
            elements.append(Paragraph(escape(card["record"]), styles["mono"]))
        for mapping in (card.get("kv"), card.get("tags"), card.get("policy_kv")):
            kv = _kv_table(mapping, styles, width)
            if kv:
                elements.append(kv)
        if card.get("policy_mx"):
            elements.append(Paragraph(escape(", ".join(card["policy_mx"])), styles["body"]))
        warn = _bullets(card.get("warnings"), _status_style("warn", styles["body"]))
        if warn:
            elements.append(warn)
        if not any([card.get("record"), card.get("kv"), card.get("tags"), card.get("policy_kv"), card.get("policy_mx"), card.get("warnings")]):
            elements.append(Paragraph("sin registro publicado", styles["muted"]))

    elif kind == "list":
        if card.get("providers"):
            elements.append(Paragraph(f"Proveedor detectado: {escape(', '.join(card['providers']))}", styles["muted"]))
        hostnames = card.get("hostnames") or []
        if hostnames:
            elements.append(Paragraph(escape(", ".join(hostnames)), styles["body"]))
        else:
            elements.append(Paragraph("sin nameservers", styles["muted"]))
        warn = _bullets(card.get("warnings"), _status_style("warn", styles["body"]))
        if warn:
            elements.append(warn)

    elif kind == "mx":
        hosts = card.get("hosts") or []
        if hosts:
            for host in hosts:
                flags = ", ".join(
                    f'<font color="{_hex(STATUS_COLORS["ok"])}">{escape(name)}</font>' if value
                    else f'<font color="{_hex(FAINT)}">{escape(name)}</font>'
                    for name, value in host["flags"]
                ) or "—"
                line = f"{escape(host['hostname'])} (prio {escape(str(host['preference']))}) — {flags}"
                elements.append(Paragraph(line, styles["body"]))
        else:
            elements.append(Paragraph("sin registros MX", styles["muted"]))
        warn = _bullets(card.get("warnings"), _status_style("warn", styles["body"]))
        if warn:
            elements.append(warn)

    elif kind == "dane":
        hosts = card.get("hosts") or []
        if hosts:
            for host in hosts:
                flags = ", ".join(
                    f'<font color="{_hex(STATUS_COLORS["ok"])}">{escape(name)}</font>' if value
                    else f'<font color="{_hex(FAINT)}">{escape(name)}</font>'
                    for name, value in [("tlsa", host["has_tlsa"]), ("dnssec", host["dnssec"])]
                )
                elements.append(Paragraph(f"{escape(host['hostname'])} — {flags}", styles["body"]))
        else:
            elements.append(Paragraph("sin registros MX", styles["muted"]))

    elif kind == "dkim":
        found = card.get("found") or []
        if found:
            elements.append(Paragraph("Al menos un selector DKIM publicado.", _status_style("ok", styles["body"])))
            for entry in found:
                status_text = "inválido" if not entry.get("valid") else f"{entry.get('key_type', '')} {entry.get('key_size', '')}".strip()
                color_key = "fail" if not entry.get("valid") else "ok"
                line = f"{escape(entry['selector'])}._domainkey — <font color=\"{_hex(STATUS_COLORS[color_key])}\">{escape(status_text)}</font>"
                elements.append(Paragraph(line, styles["body"]))
                if entry.get("error"):
                    elements.append(Paragraph(escape(entry["error"]), _status_style("fail", styles["muted"])))
                if entry.get("record"):
                    elements.append(Paragraph(escape(entry["record"]), styles["mono"]))
        else:
            elements.append(Paragraph("No se encontró DKIM en los selectores probados. El dominio podría usar un selector personalizado fuera de este análisis.", _status_style("fail", styles["body"])))
        if card.get("not_found"):
            elements.append(Paragraph(f"selectores probados sin resultado: {escape(', '.join(card['not_found']))}", styles["muted"]))

    return elements


def _card_flowable(card, styles, width):
    """Tarjeta completa (encabezado + contenido) envuelta en una caja, sin partirse entre páginas."""
    inner = width - 2 * CARD_PAD
    content = [_header_row(card["title"], card["status"], styles, inner)] + _card_content(card, styles, inner)
    return KeepTogether([_boxed(content, width=width), Spacer(1, 8)])


def _risk_flowable(risk, styles, width):
    """Caja de un riesgo priorizado (título + severidad + mitigación + ejemplo DNS opcional)."""
    inner = width - 2 * CARD_PAD
    header = Table(
        [[Paragraph(escape(risk["title"]), styles["card_title"]),
          Paragraph(escape(risk["severity"]), ParagraphStyle("sev", parent=styles["card_title"], fontSize=7.5, textColor=SEVERITY_COLORS.get(risk["severity"], MUTED), alignment=TA_RIGHT))]],
        colWidths=[inner * 0.7, inner * 0.3],
    )
    header.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    content = [header, Paragraph(escape(risk["mitigation"]), styles["muted"])]
    example = risk.get("dns_example")
    if example:
        content.append(Paragraph(f"{escape(example['host'])} · {escape(example['type'])}", styles["muted"]))
        content.append(Paragraph(escape(example["value"]), styles["mono"]))
    return KeepTogether([_boxed(content, width=width), Spacer(1, 8)])


def build_pdf_bytes(context):
    """Arma el PDF completo del reporte a partir del mismo contexto usado para renderizar check_result.html."""
    styles = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=LETTER,
        topMargin=TOP_MARGIN, bottomMargin=BOTTOM_MARGIN, leftMargin=16 * mm, rightMargin=16 * mm,
        title=f"Reporte DMARC - {context['result_domain']}",
    )
    width = doc.width
    elements = [
        Paragraph(f"{escape(context['result_domain'])} &middot; generado el {escape(context['generated_at'])}", styles["subtitle"]),
        Spacer(1, 14),
    ]

    if context.get("ai_summary"):
        summary_text = escape(context["ai_summary"]).replace("\n", "<br/>")
        elements.append(_boxed(
            [Paragraph("RESUMEN", styles["h2"]), Spacer(1, 4), Paragraph(summary_text, styles["summary"])],
            bg=BRAND_BG, border=BRAND_BORDER, width=width,
        ))
        elements.append(Spacer(1, 12))

    summary = context["summary"]
    score = summary["score"]
    score_status = "ok" if score >= 80 else "warn" if score >= 50 else "fail"
    inner = width - 2 * CARD_PAD
    score_line = Table([[
        Paragraph(escape(context["result_domain"]), styles["card_title"]),
        Paragraph(f"{score}% saludable", ParagraphStyle("score", parent=styles["card_title"], textColor=STATUS_COLORS[score_status], alignment=TA_RIGHT)),
    ]], colWidths=[inner * 0.7, inner * 0.3])
    score_line.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
    ]))
    counts_line = Paragraph(
        f'<font color="{_hex(STATUS_COLORS["ok"])}">{summary["ok"]} ok</font> &middot; '
        f'<font color="{_hex(STATUS_COLORS["warn"])}">{summary["warn"]} advertencias</font> &middot; '
        f'<font color="{_hex(STATUS_COLORS["fail"])}">{summary["fail"]} fallas</font>',
        styles["muted"],
    )
    elements.append(_boxed([score_line, Spacer(1, 4), counts_line], width=width))
    elements.append(Spacer(1, 14))

    risks = context.get("risks") or []
    if risks:
        elements.append(Paragraph("RIESGOS Y QUÉ HACER", styles["h2"]))
        elements.append(Spacer(1, 6))
        for risk in risks:
            elements.append(_risk_flowable(risk, styles, width))

    for card in context["cards"]:
        elements.append(_card_flowable(card, styles, width))

    doc.build(elements, onFirstPage=_draw_page_furniture, onLaterPages=_draw_page_furniture)
    return buf.getvalue()


def _alert_flowable(alert, styles, width):
    """Caja de una alerta del dashboard de monitoreo: badge de tipo + fecha, y el mensaje debajo."""
    inner = width - 2 * CARD_PAD
    badge_color = STATUS_COLORS["fail"] if alert.kind == "unknown_sender" else STATUS_COLORS["warn"]
    header = Table([[
        Paragraph(escape(alert.kind_label), ParagraphStyle("alert_badge", parent=styles["card_title"], fontSize=7.5, textColor=badge_color)),
        Paragraph(escape(alert.created_at.strftime("%Y-%m-%d %H:%M")) + " UTC", ParagraphStyle("alert_ts", parent=styles["muted"], alignment=TA_RIGHT)),
    ]], colWidths=[inner * 0.5, inner * 0.5])
    header.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    content = [header, Spacer(1, 4), Paragraph(escape(alert.message), styles["body"])]
    return KeepTogether([_boxed(content, width=width), Spacer(1, 8)])


def _report_flowable(report, styles, width):
    """Caja de un reporte DMARC agregado: organización + fecha de recepción, y cada remitente real debajo."""
    inner = width - 2 * CARD_PAD
    header = Table([[
        Paragraph(escape(report.org_name or "origen desconocido"), styles["card_title"]),
        Paragraph(f"recibido {escape(report.received_at.strftime('%Y-%m-%d %H:%M'))} UTC", ParagraphStyle("report_ts", parent=styles["muted"], alignment=TA_RIGHT)),
    ]], colWidths=[inner * 0.6, inner * 0.4])
    header.setStyle(TableStyle([
        ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0), ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    content = [header]
    records = report.records.all() if hasattr(report.records, "all") else list(report.records)
    # Un reporte real puede traer cientos de remitentes (visto: 414 en uno solo) —
    # una caja de una sola celda no puede partirse entre páginas, así que sin este
    # tope un reporte grande revienta el layout entero (LayoutError: caja más alta
    # que la página). Se recorta y se avisa cuánto quedó afuera, nunca en silencio.
    shown = records[:MAX_REPORT_RECORDS]
    for record in shown:
        org = escape(record.source_asn_org or "sin identificar")
        country = f", {escape(record.source_country)}" if record.source_country else ""
        spf_color = STATUS_COLORS["ok"] if record.spf_aligned else STATUS_COLORS["fail"]
        dkim_color = STATUS_COLORS["ok"] if record.dkim_aligned else STATUS_COLORS["fail"]
        line = (
            f'{escape(record.source_ip)} <font color="{_hex(FAINT)}">({org}{country}) &times;{record.count}</font>'
            f'&nbsp;&nbsp;<font color="{_hex(spf_color)}">spf</font> <font color="{_hex(dkim_color)}">dkim</font>'
        )
        content.append(Paragraph(line, styles["body"]))
    hidden = len(records) - len(shown)
    if hidden > 0:
        content.append(Paragraph(f"+ {hidden} remitentes más — revisa el dashboard para la lista completa.", styles["muted"]))
    return KeepTogether([_boxed(content, width=width), Spacer(1, 8)])


def build_dashboard_pdf_bytes(context):
    """Arma el PDF del dashboard de monitoreo (alertas recientes + reportes DMARC recibidos) de un dominio."""
    monitored = context["monitored"]
    styles = _styles()
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=LETTER,
        topMargin=TOP_MARGIN, bottomMargin=BOTTOM_MARGIN, leftMargin=16 * mm, rightMargin=16 * mm,
        title=f"Monitoreo DMARC - {monitored.domain}",
    )
    width = doc.width
    elements = [
        Paragraph(f"{escape(monitored.domain)} &middot; generado el {escape(context['generated_at'])}", styles["subtitle"]),
        Spacer(1, 2),
        Paragraph(
            f"registrado el {escape(monitored.created_at.strftime('%Y-%m-%d'))} &middot; alertas a {escape(monitored.owner_email)}",
            styles["muted"],
        ),
        Spacer(1, 14),
    ]

    elements.append(Paragraph("ALERTAS RECIENTES", styles["h2"]))
    elements.append(Paragraph(
        "Remitentes que enviaron correo en nombre de este dominio pero no están declarados en su SPF. "
        "No siempre es un ataque — también aparece al agregar una herramienta nueva sin sumarla todavía al SPF — "
        "pero si no reconoces el remitente, vale la pena investigarlo.",
        styles["help"],
    ))
    elements.append(Spacer(1, 6))
    alerts = context.get("alerts") or []
    if alerts:
        for alert in alerts:
            elements.append(_alert_flowable(alert, styles, width))
    else:
        elements.append(Paragraph("Sin alertas por ahora.", styles["muted"]))
    elements.append(Spacer(1, 10))

    elements.append(Paragraph("REPORTES DMARC RECIBIDOS", styles["h2"]))
    elements.append(Paragraph(
        "Un resumen que cada proveedor de correo (Gmail, Outlook, Mimecast, etc.) manda una vez al día: qué IPs "
        "enviaron correo en nombre de este dominio, cuántas veces, y si pasaron la validación SPF/DKIM. De aquí "
        f'sale la información de las alertas de arriba. Las etiquetas <font color="{_hex(STATUS_COLORS["ok"])}">spf</font>/'
        f'<font color="{_hex(STATUS_COLORS["ok"])}">dkim</font> en verde indican que ese envío pasó esa validación; '
        f'en <font color="{_hex(STATUS_COLORS["fail"])}">rojo</font>, que falló — un fallo aislado no es grave, pero '
        "si un mismo remitente falla siempre, vale la pena revisarlo.",
        styles["help"],
    ))
    elements.append(Spacer(1, 6))
    reports = context.get("reports") or []
    if reports:
        for report in reports:
            elements.append(_report_flowable(report, styles, width))
    else:
        elements.append(Paragraph("Sin reportes todavía.", styles["muted"]))

    doc.build(elements, onFirstPage=_draw_page_furniture, onLaterPages=_draw_page_furniture)
    return buf.getvalue()
