"""Icônes SVG inline (style Lucide) pour le dashboard NZOYI.

Streamlit conserve le SVG inline via ``st.markdown(unsafe_allow_html=True)``
(contrairement aux ``<script>``), donc on remplace TOUS les emojis par ces
tracés vectoriels. Style Lucide : ``stroke``, ``fill=none``, ``stroke-width=2``,
coins arrondis.
"""

from __future__ import annotations

# Tracés Lucide (contenu interne du <svg>, viewBox 0 0 24 24).
_PATHS: dict[str, str] = {
    "search": '<circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/>',
    "list": '<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>',
    "activity": '<path d="M22 12h-4l-3 9L9 3l-3 9H2"/>',
    "eye-off": (
        '<path d="M9.9 9.9a3 3 0 1 0 4.2 4.2M10.7 5.1A10.4 10.4 0 0 1 12 5c7 0 10 7 10 7'
        'a13 13 0 0 1-1.7 2.7M6.6 6.6A13.5 13.5 0 0 0 2 12s3 7 10 7a9.7 9.7 0 0 0 5.4-1.6"/>'
        '<path d="M2 2l20 20"/>'
    ),
    "crosshair": '<circle cx="12" cy="12" r="10"/><path d="M22 12h-4M6 12H2M12 6V2M12 22v-4"/>',
    "shield": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    "cpu": (
        '<rect x="4" y="4" width="16" height="16" rx="2"/>'
        '<rect x="9" y="9" width="6" height="6"/>'
        '<path d="M9 1v3M15 1v3M9 20v3M15 20v3M20 9h3M20 14h3M1 9h3M1 14h3"/>'
    ),
    "terminal": '<path d="M4 17l6-6-6-6M12 19h8"/>',
    "share-2": (
        '<circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/>'
        '<circle cx="18" cy="19" r="3"/><path d="m8.6 13.5 6.8 4M15.4 6.5l-6.8 4"/>'
    ),
    "radar": (
        '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/>'
        '<circle cx="12" cy="12" r="2"/><path d="M12 12 20 6"/>'
    ),
    "zap": '<path d="M13 2 3 14h9l-1 8 10-12h-9l1-8z"/>',
    "play": '<polygon points="6 3 20 12 6 21 6 3"/>',
    "square": '<rect x="4" y="4" width="16" height="16" rx="1"/>',
    "pause": (
        '<rect x="6" y="4" width="4" height="16" rx="1"/>'
        '<rect x="14" y="4" width="4" height="16" rx="1"/>'
    ),
    "rotate-cw": '<path d="M21 12a9 9 0 1 1-3-6.7L21 8"/><path d="M21 3v5h-5"/>',
    "sliders": (
        '<path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3'
        'M1 14h6M9 8h6M17 16h6"/>'
    ),
    "target": (
        '<circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/>'
        '<circle cx="12" cy="12" r="2"/>'
    ),
    "gauge": '<path d="m12 14 4-4"/><path d="M3.34 19a10 10 0 1 1 17.32 0"/>',
    "bar-chart": (
        '<path d="M3 3v18h18"/><rect x="7" y="10" width="3" height="8"/>'
        '<rect x="12" y="6" width="3" height="12"/><rect x="17" y="13" width="3" height="5"/>'
    ),
    "alert-triangle": (
        '<path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3'
        'L13.71 3.86a2 2 0 0 0-3.42 0z"/><path d="M12 9v4"/><path d="M12 17h.01"/>'
    ),
    "check": '<path d="M20 6 9 17l-5-5"/>',
    "x": '<path d="M18 6 6 18M6 6l12 12"/>',
    "layers": (
        '<path d="m12 2 9 4.9-9 4.9L3 6.9 12 2z"/>'
        '<path d="m3 12 9 4.9 9-4.9"/><path d="m3 17 9 4.9 9-4.9"/>'
    ),
    "clock": '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
}


def icon(name: str, size: int = 18, color: str = "#00ff7f") -> str:
    """Retourne un ``<svg>`` Lucide inline prêt à injecter via ``st.markdown``.

    Args:
        name: Clé de l'icône (voir ``_PATHS``). Repli sur ``terminal``.
        size: Largeur/hauteur en pixels.
        color: Couleur du trait (``stroke``).

    Returns:
        Le markup SVG complet, aligné verticalement sur le texte.
    """
    p = _PATHS.get(name, _PATHS["terminal"])
    return (
        f'<svg width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
        f'stroke="{color}" stroke-width="2" stroke-linecap="round" '
        f'stroke-linejoin="round" style="vertical-align:-3px">{p}</svg>'
    )
