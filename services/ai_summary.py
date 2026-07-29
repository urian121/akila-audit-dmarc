import os

from openai import OpenAI

DEFAULT_MODEL = "gpt-4o-mini"

SYSTEM_PROMPT = (
    "Eres un analista de seguridad de correo electrónico. Recibes el resultado ya "
    "traducido a lenguaje simple de una auditoría de SPF, DMARC, DKIM, MX, DNSSEC, "
    "MTA-STS, TLS-RPT y BIMI para un dominio. Responde en español, en un máximo de "
    "6 líneas, directo y fácil de entender para alguien no técnico. Di qué se "
    "encontró, qué tan protegido está el dominio contra suplantación de correo "
    "(spoofing/phishing), y si algo falla, qué es lo más importante a corregir. "
    "No repitas registros DNS crudos ni jerga técnica. No uses markdown ni listas, "
    "solo texto plano en líneas cortas."
)


def _client():
    """Crea el cliente de OpenAI con la key del .env, o None si no está configurada."""
    api_key = os.environ.get("OPENAI_PROJECT_API_KEY")
    if not api_key:
        return None
    return OpenAI(api_key=api_key)


def _describe_card(card):
    """Convierte una tarjeta ya armada (ver services/card_builder.py) en una línea de texto plano."""
    parts = [f"{card['title']} [{card['status'].upper()}]"]

    if card.get("message"):
        parts.append(card["message"])
    if card.get("text"):
        parts.append(card["text"])
    if card.get("explanations"):
        parts.append("; ".join(card["explanations"]))

    if card.get("kind") == "dkim":
        if card.get("found"):
            selectores = ", ".join(e["selector"] for e in card["found"])
            parts.append(f"Selectores DKIM publicados: {selectores}")
        else:
            parts.append("Ningún selector DKIM común tiene registro publicado")

    if card.get("kind") == "mx" and card.get("hosts"):
        hosts = ", ".join(h["hostname"] for h in card["hosts"])
        parts.append(f"Servidores de correo: {hosts}")

    if card.get("warnings"):
        parts.append("Advertencias: " + "; ".join(card["warnings"]))

    return " — ".join(parts)


def _build_prompt(domain, cards):
    """Arma el mensaje que se le manda al modelo a partir de las tarjetas ya interpretadas."""
    lineas = [_describe_card(card) for card in cards]
    return f"Dominio analizado: {domain}\n\n" + "\n".join(lineas)


def generate_summary(domain, cards):
    """Genera un resumen de máximo 6 líneas sobre la salud de autenticación de correo del dominio. Devuelve None si la IA no está configurada o falla."""
    client = _client()
    if client is None:
        return None

    try:
        response = client.chat.completions.create(
            model=DEFAULT_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": _build_prompt(domain, cards)},
            ],
            temperature=0.3,
            max_tokens=300,
            timeout=15,
        )
        return response.choices[0].message.content.strip()
    except Exception:
        return None
