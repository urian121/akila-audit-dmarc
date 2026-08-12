"""Agente especializado en salud DMARC de un dominio: sintetiza tendencias, impacto y desglose de
reportes ya calculados (no hace ninguna consulta nueva) en un veredicto accionable — qué está bien,
qué necesita atención, y qué es crítico. Usado solo desde /tendencias/<token>/analisis-ia (fragmento
htmx cargado aparte, igual que el estado del protocolo, para no bloquear la carga inicial de la página).
"""
import json
import os

from openai import OpenAI

DEFAULT_MODEL = "gpt-4o-mini"

SYSTEM_PROMPT = (
    "Eres un analista senior de seguridad de correo electrónico, especializado en DMARC. Recibís "
    "un resumen estructurado en texto plano sobre un dominio: su política DMARC, cuánto correo se "
    "autentica correctamente, quién reporta, y qué remitentes fallan. Tu trabajo es evaluar la "
    "salud real de ese dominio contra suplantación de correo (spoofing/phishing) y devolver "
    "ÚNICAMENTE un JSON válido (sin texto fuera del JSON, sin markdown) con esta forma exacta:\n"
    '{"health_score": <entero 0-100>, "verdict": "excelente|bueno|regular|malo", '
    '"summary": "1-2 oraciones", "strengths": ["..."], "needs_attention": ["..."], "critical": ["..."]}\n'
    "Máximo 4 puntos por lista, en español, directos y orientados a acción (qué hacer, no solo qué "
    "pasa) — no repitas números que ya aparecen en el resumen, interpretalos. Si no hay nada "
    "crítico, 'critical' debe ser una lista vacía, no inventar un riesgo menor para llenarla."
)


def _client():
    """Crea el cliente de OpenAI con la key del .env, o None si no está configurada."""
    api_key = os.environ.get("OPENAI_PROJECT_API_KEY")
    if not api_key:
        return None
    return OpenAI(api_key=api_key)


def _build_prompt(monitored, trend_data, impact, report_breakdown, top_affected_senders):
    """Arma el resumen en texto plano que se le manda al modelo, a partir de los datos ya calculados
    en la página de Tendencias (get_trends_data/get_impact_analysis/get_report_breakdown) más los
    primeros remitentes afectados (list_affected_senders(), calculado aparte porque ya no viene
    incluido en get_impact_analysis() — esa lista ahora vive paginada en su propia tabla)."""
    lines = [
        f"Dominio: {monitored.domain}",
        f"Política DMARC actual: p={impact.get('current_policy') or 'sin registro DMARC detectado'}",
        f"Reportes DMARC agregados recibidos en el período: {impact.get('total_reports')}",
        f"Mensajes totales reportados: {impact.get('total_messages')}",
        f"Tasa de cumplimiento DMARC (correo que alineó SPF o DKIM): {impact.get('pass_rate')}%",
        f"Mensajes que NO pasaron DMARC: {impact.get('total_fail')}",
        f"Fuentes (IPs) únicas que enviaron correo en nombre de este dominio: {impact.get('unique_sources')}",
    ]
    if report_breakdown.get("has_spf"):
        lines.append(f"Resultado de política SPF: {report_breakdown['spf_pass']} pasaron, {report_breakdown['spf_fail']} fallaron")
    if report_breakdown.get("has_dkim"):
        lines.append(f"Resultado de política DKIM: {report_breakdown['dkim_pass']} pasaron, {report_breakdown['dkim_fail']} fallaron")
    if report_breakdown.get("orgs"):
        orgs = ", ".join(f"{o['name']} ({o['count']} correos)" for o in report_breakdown["orgs"])
        lines.append(f"Organizaciones que mandaron reportes: {orgs}")
    if top_affected_senders:
        senders = ", ".join(f"{s['source_asn_org']} ({s['count']} correos, IP {s['source_ip']})" for s in top_affected_senders)
        lines.append(f"Principales remitentes que fallan DMARC hoy (se verían afectados si se refuerza la política): {senders}")
    return "\n".join(lines)


def generate_health_analysis(monitored, trend_data, impact, report_breakdown, top_affected_senders=None):
    """Genera el análisis de salud DMARC del dominio. Devuelve None si la IA no está configurada,
    falla, tarda, o responde algo que no se puede interpretar como el JSON esperado — en cualquiera
    de esos casos el resto de la página de Tendencias sigue funcionando igual, esto es 100% opcional."""
    client = _client()
    if client is None:
        return None

    try:
        response = client.chat.completions.create(
            model=DEFAULT_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _build_prompt(monitored, trend_data, impact, report_breakdown, top_affected_senders or [])},
            ],
            temperature=0.3,
            max_tokens=500,
            timeout=20,
            response_format={"type": "json_object"},
        )
        data = json.loads(response.choices[0].message.content)
        data["health_score"] = max(0, min(100, int(data.get("health_score", 0))))
        data["verdict"] = str(data.get("verdict") or "regular").lower()
        data.setdefault("summary", "")
        data.setdefault("strengths", [])
        data.setdefault("needs_attention", [])
        data.setdefault("critical", [])
        return data
    except Exception as error:
        print(f"[domain_health_analysis] error generando análisis para {monitored.domain}: {error}")
        return None
