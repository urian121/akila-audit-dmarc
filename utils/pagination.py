def paginate(items, page, per_page):
    """Pagina una lista ya armada en memoria: recorta a la página pedida (clampeada al rango
    válido) y devuelve items/total_items/page/total_pages — misma forma que ya esperan los
    templates de tabla (compliance_rows.html, domain_senders_table.html, etc.)."""
    total_items = len(items)
    per_page = max(1, per_page)
    total_pages = max(1, (total_items + per_page - 1) // per_page)
    page = min(max(1, page), total_pages)
    start = (page - 1) * per_page
    return {
        "items": items[start:start + per_page],
        "total_items": total_items,
        "page": page,
        "total_pages": total_pages,
    }
