from utils.formatting import (
    flatten_tag_value,
    friendly_error_message,
    is_absence_error,
    is_timeout_error,
    scalar_items,
    translate_warnings,
)

# Etiqueta y clases Tailwind del badge de estado que se muestra en cada tarjeta.
STATUS_META = {
    "ok":   ("OK", "bg-emerald-50 text-emerald-700 border-emerald-200"),
    "warn": ("ADVERTENCIA", "bg-amber-50 text-amber-700 border-amber-200"),
    "fail": ("FALLA", "bg-rose-50 text-rose-700 border-rose-200"),
    "na":   ("N/D", "bg-zinc-100 text-zinc-500 border-zinc-200"),
}

# Protocolos opcionales/avanzados: si el registro simplemente no existe, es
# una recomendación (ADVERTENCIA), no una falla como un SPF/DMARC roto.
SOFT_ABSENCE_KEYS = ("mta_sts", "smtp_tls_reporting", "bimi")

# Heurística por hostname de NS -> proveedor de DNS. No es oficial ni
# exhaustiva — sólo para mostrarle al usuario quién administra el DNS del
# dominio, igual idea que KNOWN_MX_PROVIDERS pero para nameservers.
KNOWN_DNS_PROVIDERS = [
    ("Cloudflare", "cloudflare.com"),
    ("Amazon Route 53", "awsdns"),
    ("Google Cloud DNS", "googledomains.com"),
    ("Microsoft Azure DNS", "azure-dns."),
    ("DNS Made Easy", "dnsmadeeasy.com"),
    ("NS1", "nsone.net"),
    ("Akamai Edge DNS", "akam.net"),
    ("GoDaddy", "domaincontrol.com"),
    ("Namecheap", "registrar-servers.com"),
    ("DigitalOcean", "digitalocean.com"),
    ("Hetzner", "hetzner."),
    ("Bluehost", "bluehost.com"),
    ("Hostinger", "dns-parking.com"),
    ("OVHcloud", "ovh.net"),
    ("Porkbun", "porkbun.com"),
    ("Squarespace", "squarespace.com"),
    ("Gandi", "gandi.net"),
    ("Vercel", "vercel-dns.com"),
]


def detect_dns_providers(hostnames):
    """Identifica el/los proveedor(es) de DNS del dominio a partir de sus nameservers, por coincidencia de texto conocida."""
    found = []
    for label, needle in KNOWN_DNS_PROVIDERS:
        if label not in found and any(needle in h.lower() for h in hostnames):
            found.append(label)
    return found

# Explicación corta de cada protocolo, mostrada bajo el título de su tarjeta.
PROTOCOL_HELP = {
    "DNSSEC": "Firma criptográficamente las respuestas DNS del dominio para evitar que sean falsificadas.",
    "SPF": "Define qué servidores pueden enviar correos en nombre de este dominio.",
    "DMARC": "Usa los resultados de SPF y DKIM para decidir si aceptar, poner en cuarentena o rechazar un correo, y para generar reportes.",
    "DKIM": "Firma digitalmente los correos para garantizar que no fueron alterados en el camino.",
    "MX": "Indica qué servidores reciben el correo de este dominio.",
    "DANE": "Ata el certificado TLS de tus servidores de correo a un registro DNS (TLSA), firmado con DNSSEC, para evitar que alguien intercepte la conexión con un certificado falso.",
    "MTA-STS": "Obliga a que el correo entrante se transporte siempre por una conexión cifrada (TLS).",
    "TLS-RPT": "Recibe reportes cuando falla el cifrado TLS al entregar correo a este dominio.",
    "BIMI": "Muestra el logo de la marca junto al correo, si DMARC está en cuarentena o rechazo.",
    "Nameservers": "Servidores DNS autoritativos para este dominio.",
}

# p= / sp= de DMARC: nombre corto y explicación en lenguaje simple.
DMARC_POLICY_LABELS = {
    "none": ("Ninguna", "Solo monitorea, no bloquea ni pone en cuarentena ningún correo."),
    "quarantine": ("Cuarentena", "Envía los correos sospechosos a la carpeta de spam."),
    "reject": ("Rechazar", "Bloquea por completo los correos que no pasan la validación — la política más segura."),
}

# adkim= / aspf= de DMARC: "s" (strict) o "r" (relaxed).
DMARC_ALIGNMENT_LABELS = {"s": "estricta", "r": "relajada"}

# Calificador del mecanismo "all" al final de un registro SPF.
SPF_ALL_LABELS = {
    "pass": "Cualquier otro servidor puede enviar correos (+all) — configuración insegura.",
    "neutral": "Los demás servidores no se validan (?all).",
    "softfail": "Los demás servidores generan SoftFail (~all): se marcan como sospechosos, pero no se rechazan.",
    "fail": "Los demás servidores son rechazados (-all) — la opción más estricta.",
}

# Cómo describir cada tipo de mecanismo SPF en lenguaje simple — (prefijo, valor a resaltar o
# None, sufijo). El valor (el hostname/IP real) se resalta aparte en la tarjeta; prefijo/sufijo
# son el texto plano alrededor.
SPF_MECHANISM_LABELS = {
    "include": lambda value: ("", value, " puede enviar correos en nombre de este dominio."),
    "ip4": lambda value: ("El rango de IPs ", value, " puede enviar correos."),
    "ip6": lambda value: ("El rango de IPs ", value, " puede enviar correos."),
    "a": lambda value: ("El servidor del registro A ", value, " puede enviar correos.") if value
        else ("", None, "El servidor del registro A de este dominio puede enviar correos."),
    "mx": lambda value: ("Los servidores de correo (MX) de ", value, " pueden enviar correos.") if value
        else ("", None, "Los servidores de correo (MX) de este dominio pueden enviar correos."),
    "exists": lambda value: ("Se valida mediante una consulta a ", value, "."),
    "ptr": lambda _value: ("", None, "Se valida mediante DNS inverso (PTR) — mecanismo obsoleto, poco recomendado."),
}


def status_of(section):
    """Clasifica una sección del resultado de checkdmarc en ok/warn/fail/na.

    Un timeout de DNS siempre es 'na' (no pudimos verificar), nunca 'fail' —
    no es evidencia de que el protocolo esté mal configurado, sólo de que la
    consulta no respondió a tiempo.
    """
    if section is None:
        return "na"
    if isinstance(section, bool):
        return "ok" if section else "fail"
    if isinstance(section, dict):
        error = section.get("error")
        if error:
            return "na" if is_timeout_error(error) else "fail"
        if section.get("valid") is False:
            return "fail"
        if section.get("warnings"):
            return "warn"
        return "ok"
    return "na"


def record_status(section, soft_absence=False):
    """Como status_of, pero permite bajar a 'warn' cuando el error es sólo ausencia del registro."""
    if not section:
        return "na"
    error = section.get("error")
    if error:
        if is_timeout_error(error):
            return "na"
        if soft_absence and is_absence_error(error):
            return "warn"
        return "fail"
    return status_of(section)


def base_card(title, status, kind, **extra):
    """Arma el dict base de una tarjeta: título, badge de estado, ayuda contextual y tipo de contenido."""
    label, cls = STATUS_META.get(status, STATUS_META["na"])
    return {
        "title": title, "status": status,
        "badge_label": label, "badge_cls": cls,
        "kind": kind, "help_text": PROTOCOL_HELP.get(title),
        **extra,
    }


def record_card(title, section, soft_absence=False):
    """Construye la tarjeta de un protocolo basado en registro DNS (MTA-STS, TLS-RPT, BIMI)."""
    if not section:
        return base_card(title, "na", "empty")
    status = record_status(section, soft_absence=soft_absence)
    if section.get("error"):
        error = section["error"]
        if is_timeout_error(error):
            message = friendly_error_message(error)
        elif soft_absence and is_absence_error(error):
            message = f"No se encontró un registro de {title} para este dominio."
        else:
            message = error
        return base_card(title, status, "error", message=message)

    policy = section.get("policy") or {}
    return base_card(
        title, status, "record",
        record=section.get("record"),
        kv=scalar_items(section, skip=("record", "warnings", "tags", "policy", "valid")),
        tags={k: flatten_tag_value(v) for k, v in (section.get("tags") or {}).items()},
        policy_kv=scalar_items(policy, skip=("mx",)),
        policy_mx=policy.get("mx") or [],
        warnings=translate_warnings(section.get("warnings")),
    )


def dmarc_policy_explanation(label_prefix, raw_value):
    """Traduce un valor de política DMARC (p=/sp=) a una frase en lenguaje simple."""
    label, description = DMARC_POLICY_LABELS.get(raw_value, (raw_value, None))
    line = f"{label_prefix}: {label}"
    if description:
        line += f" — {description}"
    return line


def dmarc_card(section):
    """Construye la tarjeta de DMARC explicando la política (p=) en lenguaje simple."""
    if not section:
        return base_card("DMARC", "na", "dmarc", has_record=False)
    status = status_of(section)
    if section.get("error"):
        return base_card("DMARC", status, "dmarc", has_record=False, message=friendly_error_message(section["error"]))

    tags = section.get("tags") or {}
    explanations = []

    if "p" in tags:
        explanations.append(dmarc_policy_explanation("Política", flatten_tag_value(tags["p"])))
    if tags.get("sp", {}).get("explicit"):
        explanations.append(dmarc_policy_explanation("Política para subdominios", flatten_tag_value(tags["sp"])))
    if "pct" in tags:
        explanations.append(f"Aplica al {flatten_tag_value(tags['pct'])}% de los correos.")
    if "aspf" in tags:
        value = flatten_tag_value(tags["aspf"])
        explanations.append(f"Alineación SPF {DMARC_ALIGNMENT_LABELS.get(value, value)}.")
    if "adkim" in tags:
        value = flatten_tag_value(tags["adkim"])
        explanations.append(f"Alineación DKIM {DMARC_ALIGNMENT_LABELS.get(value, value)}.")
    if "rua" in tags:
        explanations.append(f"Envía reportes agregados a: {flatten_tag_value(tags['rua'])}")
    if "ruf" in tags:
        explanations.append(f"Envía reportes forenses a: {flatten_tag_value(tags['ruf'])}")

    return base_card(
        "DMARC", status, "dmarc",
        has_record=True,
        record=section.get("record"),
        explanations=explanations,
        warnings=translate_warnings(section.get("warnings")),
    )


def spf_card(section):
    """Construye la tarjeta de SPF explicando en lenguaje simple quién puede enviar correo."""
    if not section:
        return base_card("SPF", "na", "spf", has_record=False)
    status = status_of(section)
    if section.get("error"):
        return base_card("SPF", status, "spf", has_record=False, message=friendly_error_message(section["error"]))

    parsed = section.get("parsed") or {}
    mechanisms = []
    for mechanism in parsed.get("mechanisms") or []:
        kind = mechanism.get("mechanism")
        value = mechanism.get("value") or ""
        describe = SPF_MECHANISM_LABELS.get(kind)
        if describe:
            prefix, highlight, suffix = describe(value)
        else:
            prefix, highlight, suffix = "", (value or kind), ""
        mechanisms.append({"prefix": prefix, "value": highlight, "suffix": suffix})

    all_qualifier = parsed.get("all")
    all_explanation = None
    if all_qualifier:
        all_explanation = SPF_ALL_LABELS.get(all_qualifier, f"Calificador 'all' desconocido: {all_qualifier}")

    return base_card(
        "SPF", status, "spf",
        has_record=True,
        record=section.get("record"),
        mechanisms=mechanisms,
        all_explanation=all_explanation,
        warnings=translate_warnings(section.get("warnings")),
    )


def dnssec_card(value):
    """Construye la tarjeta de DNSSEC a partir del booleano que devuelve checkdmarc."""
    status = status_of(value)
    text = "DNSSEC activo y validado" if value else "DNSSEC no está activo"
    return base_card("DNSSEC", status, "text", text=text)


def ns_card(section):
    """Construye la tarjeta de Nameservers."""
    if not section:
        return base_card("Nameservers", "na", "empty")
    status = status_of(section)
    if section.get("error"):
        return base_card("Nameservers", status, "error", message=friendly_error_message(section["error"]))
    hostnames = section.get("hostnames") or []
    return base_card(
        "Nameservers", status, "list",
        hostnames=hostnames,
        providers=detect_dns_providers(hostnames),
        warnings=translate_warnings(section.get("warnings")),
    )


def visible_mx_warnings(section):
    """Filtra los warnings de MX descartando el ruido de DNS inverso (PTR): suele ser de la infraestructura del proveedor de correo (ej. Google), no del dominio auditado."""
    return [w for w in (section.get("warnings") or []) if "reverse dns" not in w.lower()]


def mx_status(section):
    """Estado de MX basado sólo en los warnings que realmente se muestran (sin el ruido de PTR)."""
    if not section:
        return "na"
    error = section.get("error")
    if error:
        return "na" if is_timeout_error(error) else "fail"
    return "warn" if visible_mx_warnings(section) else "ok"


def mx_card(section):
    """Construye la tarjeta de MX, incluyendo los flags booleanos de cada host (ej. dnssec)."""
    if not section:
        return base_card("MX", "na", "empty")
    status = mx_status(section)
    if section.get("error"):
        return base_card("MX", status, "error", message=friendly_error_message(section["error"]))
    hosts = []
    for h in section.get("hosts") or []:
        flags = [(k, v) for k, v in h.items() if isinstance(v, bool)]
        hosts.append({
            "hostname": h.get("hostname", "?"),
            "preference": h.get("preference", "—"),
            "flags": flags,
        })
    return base_card("MX", status, "mx", hosts=hosts, warnings=translate_warnings(visible_mx_warnings(section)))


def dane_status(mx_section):
    """Estado de DANE a partir de los hosts MX que ya trae mx_card() (mismo `data['mx']`, sin
    consulta nueva): checkdmarc ya busca el registro TLSA de cada host MX dentro de check_mx() —
    es una consulta DNS pura (no requiere conectarse por SMTP), así que sí funciona en Windows,
    a diferencia de starttls/tls. Un host con TLSA pero sin DNSSEC válido es 'fail' (el TLSA no se
    puede confiar sin DNSSEC, es peor que no tener nada porque da una falsa sensación de seguridad);
    ningún host con TLSA, o solo algunos (rollout parcial), es 'warn' — es opcional."""
    if not mx_section or mx_section.get("error"):
        return "na"
    hosts = mx_section.get("hosts") or []
    if not hosts:
        return "na"
    hosts_with_tlsa = [h for h in hosts if h.get("tlsa")]
    if any(not h.get("dnssec") for h in hosts_with_tlsa):
        return "fail"
    if not hosts_with_tlsa or len(hosts_with_tlsa) < len(hosts):
        return "warn"
    return "ok"


def dane_card(mx_section):
    """Construye la tarjeta de DANE — ver dane_status() para la lógica de estado."""
    status = dane_status(mx_section)
    hosts = [
        {
            "hostname": h.get("hostname", "?"),
            "has_tlsa": bool(h.get("tlsa")),
            "dnssec": bool(h.get("dnssec")),
        }
        for h in (mx_section or {}).get("hosts") or []
    ]
    return base_card("DANE", status, "dane", hosts=hosts)


def dkim_status(entries):
    """Calcula el estado global de DKIM a partir de la lista de selectores probados."""
    if not entries:
        return "na"
    found = [e for e in entries if e.get("found")]
    if any(e.get("valid") is False for e in found):
        return "fail"
    if any(e.get("valid") for e in found):
        return "ok"
    return "warn"


def dkim_card(entries):
    """Construye la tarjeta de DKIM con los selectores encontrados y los que no dieron resultado."""
    entries = entries or []
    status = dkim_status(entries)
    found = [e for e in entries if e.get("found")]
    return base_card(
        "DKIM", status, "dkim",
        has_record=bool(found),
        found=found,
        not_found=[e["selector"] for e in entries if not e.get("found")],
    )


# Acción concreta a tomar por (protocolo, estado) — sólo fail/warn necesitan una, ok/na no.
RISK_MITIGATIONS = {
    ("DNSSEC", "fail"): "Activa DNSSEC desde tu proveedor de DNS — evita que alguien falsifique las respuestas de este dominio.",
    ("SPF", "fail"): "Publica un registro SPF que declare qué servidores pueden enviar correo en nombre de este dominio.",
    ("SPF", "warn"): "Revisa la advertencia de tu SPF — puede estar cerca del límite de 10 consultas DNS permitidas.",
    ("DMARC", "fail"): "Publica un registro DMARC — sin él, cualquiera puede enviar correo haciéndose pasar por este dominio sin que nadie se entere.",
    ("DMARC", "warn"): "Sube la política DMARC a cuarentena o rechazo cuando estés listo — hoy sólo está en modo monitoreo, no bloquea nada.",
    ("DKIM", "fail"): "Activa DKIM en tu proveedor de correo (Google Workspace, Microsoft 365, etc.) y firma los mensajes salientes.",
    ("DKIM", "warn"): "No se encontró DKIM en los selectores más comunes — confirma con tu proveedor cuál selector usa y agrégalo a la búsqueda.",
    ("MX", "fail"): "Revisa tu registro MX — sin uno válido no se puede recibir correo en este dominio.",
    ("MX", "warn"): "Revisa la advertencia de tus servidores MX con tu proveedor de correo.",
    ("DANE", "fail"): "Alguno de tus servidores de correo publica un registro TLSA sin DNSSEC válido — sin DNSSEC no se puede confiar en ese TLSA. Revisa la firma DNSSEC de ese host o quita el TLSA hasta activarla.",
    ("DANE", "warn"): "Opcional: publica un registro TLSA (con DNSSEC activo) en tus servidores de correo para atar su certificado TLS y evitar ataques de intermediario al recibir correo.",
    ("MTA-STS", "warn"): "Opcional: publica MTA-STS para forzar que el correo entrante siempre viaje cifrado.",
    ("TLS-RPT", "warn"): "Opcional: publica TLS-RPT para que te avisen si falla el cifrado del correo entrante.",
    ("BIMI", "warn"): "Opcional: BIMI muestra el logo de tu marca junto al correo, pero primero necesitas DMARC en cuarentena o rechazo.",
    ("Nameservers", "fail"): "Revisa la configuración de tus servidores DNS (NS) con tu proveedor.",
    ("Nameservers", "warn"): "Revisa la advertencia de tus servidores DNS (NS) con tu proveedor.",
}

# Severidad por estado; las advertencias de protocolos opcionales (SOFT_ABSENCE_KEYS) pesan menos.
RISK_SEVERITY = {
    "fail": ("Alta", "border-rose-200 text-rose-700 bg-rose-50"),
    "warn": ("Media", "border-amber-200 text-amber-700 bg-amber-50"),
}
RISK_SEVERITY_SOFT_WARN = ("Baja", "border-zinc-200 text-zinc-500 bg-zinc-100")
SEVERITY_RANK = {"Alta": 0, "Media": 1, "Baja": 2}
SOFT_ABSENCE_TITLES = ("MTA-STS", "TLS-RPT", "BIMI", "DANE")


def _tls_rpt_example(domain):
    """Ejemplo de registro TLS-RPT para adaptar — usa una casilla de ejemplo, no una real; el usuario debe cambiarla por una que controle."""
    if not domain:
        return None
    return {
        "host": f"_smtp._tls.{domain}",
        "type": "TXT",
        "value": f"v=TLSRPTv1; rua=mailto:tls-reports@{domain}",
    }


def build_risks(cards, domain=None):
    """A partir de las tarjetas ya armadas, arma la lista de riesgos a resolver (sólo fail/warn), con severidad y una acción concreta, de más a menos grave."""
    risks = []
    for card in cards:
        status = card["status"]
        if status not in ("fail", "warn"):
            continue
        mitigation = RISK_MITIGATIONS.get((card["title"], status))
        if not mitigation:
            continue
        if status == "warn" and card["title"] in SOFT_ABSENCE_TITLES:
            severity, severity_cls = RISK_SEVERITY_SOFT_WARN
        else:
            severity, severity_cls = RISK_SEVERITY[status]
        risk = {
            "title": card["title"],
            "severity": severity,
            "severity_cls": severity_cls,
            "mitigation": mitigation,
        }
        if card["title"] == "TLS-RPT":
            example = _tls_rpt_example(domain)
            if example:
                risk["dns_example"] = example
        risks.append(risk)
    risks.sort(key=lambda r: SEVERITY_RANK.get(r["severity"], 3))
    return risks


def build_cards(data):
    """Arma la lista completa de tarjetas (una por protocolo) para renderizar en la plantilla."""
    return [
        dnssec_card(data.get("dnssec")),
        spf_card(data.get("spf")),
        dmarc_card(data.get("dmarc")),
        dkim_card(data.get("dkim")),
        mx_card(data.get("mx")),
        dane_card(data.get("mx")),
        record_card("MTA-STS", data.get("mta_sts"), soft_absence=True),
        record_card("TLS-RPT", data.get("smtp_tls_reporting"), soft_absence=True),
        record_card("BIMI", data.get("bimi"), soft_absence=True),
        ns_card(data.get("ns")),
    ]


def build_summary(data):
    """Cuenta cuántos protocolos quedaron en ok/warn/fail para el resumen mostrado arriba de las tarjetas."""
    ok = warn = fail = 0
    for key in ("spf", "dmarc", "ns"):
        s = status_of(data.get(key))
        if s == "ok":
            ok += 1
        elif s == "warn":
            warn += 1
        elif s == "fail":
            fail += 1

    s = mx_status(data.get("mx"))
    if s == "ok":
        ok += 1
    elif s == "warn":
        warn += 1
    elif s == "fail":
        fail += 1

    s = dane_status(data.get("mx"))
    if s == "ok":
        ok += 1
    elif s == "warn":
        warn += 1
    elif s == "fail":
        fail += 1

    for key in SOFT_ABSENCE_KEYS:
        s = record_status(data.get(key), soft_absence=True)
        if s == "ok":
            ok += 1
        elif s == "warn":
            warn += 1
        elif s == "fail":
            fail += 1

    ok += 1 if status_of(data.get("dnssec")) == "ok" else 0
    fail += 1 if status_of(data.get("dnssec")) != "ok" else 0

    s = dkim_status(data.get("dkim"))
    if s == "ok":
        ok += 1
    elif s == "warn":
        warn += 1
    elif s == "fail":
        fail += 1

    total = ok + warn + fail

    def pct(count):
        """Convierte un conteo en porcentaje del total de protocolos evaluados."""
        return round((count / total) * 100) if total else 0

    # Una advertencia (protocolo opcional ausente, no roto) pesa la mitad que
    # un ok, y una falla no suma nada — coherente con SOFT_ABSENCE_KEYS.
    score = round(((ok + warn * 0.5) / total) * 100) if total else 0
    if score >= 80:
        score_color = "text-emerald-600"
    elif score >= 50:
        score_color = "text-amber-600"
    else:
        score_color = "text-rose-600"

    return {
        "ok": ok, "warn": warn, "fail": fail, "total": total,
        "ok_pct": pct(ok), "warn_pct": pct(warn), "fail_pct": pct(fail),
        "score": score, "score_color": score_color,
    }
