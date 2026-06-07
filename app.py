# ==============================================================================
# 1. IMPORTACIONES Y CONFIGURACIÓN INICIAL
# ==============================================================================
import streamlit as st
import requests
import re
import base64
import socket
import whois
import ssl
import pandas as pd
import random
from datetime import datetime
from urllib.parse import urlparse
from difflib import SequenceMatcher

# CONFIGURACIÓN DE PÁGINA (Debe ser el primer comando ejecutable de Streamlit)
st.set_page_config(
    page_title="Escudo Mayor",
    page_icon="🛡️",
    layout="centered"
)

# Carga segura de Trivia desde archivo externo
try:
    from preguntas import TRIVIA_SEGURIDAD
except ImportError:
    TRIVIA_SEGURIDAD = [
        {"pregunta": "¿El banco te pide claves por WhatsApp?", "opciones": ["Sí", "No"], "respuesta": "No", "explicacion": "Ningún banco pide contraseñas por WhatsApp o redes sociales."}
    ]

# Título Principal Estilizado e Identidad Visual (Compactada para eliminar espacios vacíos)
st.markdown("""
<div style="border-top: 3px solid #008a45; border-bottom: 3px solid #008a45; padding: 12px 0; text-align: center; margin-top: 5px; margin-bottom: 5px;">
    <h1 style="color: #008a45; margin: 0; font-size: 2.6rem; font-weight: 800; letter-spacing: 1.5px;">🛡️ Escudo Mayor</h1>
</div>
<p style='color: #4a5568; font-size: 1.15rem; text-align: center; margin-top: 8px; margin-bottom: 15px; font-weight: 500;'>Fortalecimiento Digital para el Adulto Mayor</p>
""", unsafe_allow_html=True)

# Manejo de Estados de Navegación por Solapas
if "active_tab" not in st.session_state:
    st.session_state["active_tab"] = "imagen"

# ==============================================================================
# 2. DICCIONARIOS Y CONSTANTES DE SEGURIDAD
# ==============================================================================
try:
    from blacklist import PALABRAS_PELIGRO, PALABRAS_ALERTA
except ImportError:
    PALABRAS_PELIGRO = ['transferencia', 'bloqueada', 'urgente', 'cbu', 'token', 'embargo', 'suspendida', 'afip', 'banco']
    PALABRAS_ALERTA = ['premio', 'ganador', 'sorteo', 'vencimiento', 'validar', 'oferta', 'actualizar', 'regalo']

MARCAS_OFICIALES = [
    'anses.gob.ar', 'bna.com.ar', 'bancoprovincia.com.ar', 
    'galicia.com.ar', 'macro.com.ar', 'santander.com.ar',
    'netflix.com', 'mercadolibre.com.ar', 'mercadopago.com.ar', 'pami.org.ar'
]

# Plataformas globales propensas a falsos positivos por abuso de terceros
SITIOS_CONFIANZA_GLOBAL = [
    'instagram.com', 'facebook.com', 'google.com', 'youtube.com', 
    'twitter.com', 'x.com', 'whatsapp.com', 'linkedin.com', 't.me'
]

# Safeguards para Secrets de Producción / Claves de Prueba
OCR_API_KEY = st.secrets.get("OCR_API_KEY", "PRUEBA_OCR_FREE_KEY")
GOOGLE_API_KEY = st.secrets.get("GOOGLE_API_KEY", "PRUEBA_GOOGLE_SAFE_KEY")
VT_API_KEY = st.secrets.get("VT_API_KEY", "PRUEBA_VIRUSTOTAL_KEY")
GOOGLE_SEARCH_API_KEY = st.secrets.get("GOOGLE_SEARCH_API_KEY", None)
GOOGLE_CX = st.secrets.get("GOOGLE_CX", None)

# ==============================================================================
# 3. ESTILOS VISUALES DINÁMICOS E INYECCIÓN DE CSS (TABS Y SEMÁFORO INTENSIFICADO)
# ==============================================================================
if st.session_state["active_tab"] == "imagen":
    css_tabs = """
    div[data-testid="stColumn"]:nth-of-type(1) button { background-color: #008a45 !important; color: white !important; font-weight: bold !important; height: 55px !important; font-size: 1.1rem !important; border: none !important; width: 100% !important; border-radius: 8px !important;}
    div[data-testid="stColumn"]:nth-of-type(2) button { background-color: #f1f5f9 !important; color: #475569 !important; font-weight: normal !important; height: 55px !important; font-size: 1.1rem !important; border: 1px solid #cbd5e1 !important; width: 100% !important; border-radius: 8px !important;}
    """
else:
    css_tabs = """
    div[data-testid="stColumn"]:nth-of-type(1) button { background-color: #f1f5f9 !important; color: #475569 !important; font-weight: normal !important; height: 55px !important; font-size: 1.1rem !important; border: 1px solid #cbd5e1 !important; width: 100% !important; border-radius: 8px !important;}
    div[data-testid="stColumn"]:nth-of-type(2) button { background-color: #008a45 !important; color: white !important; font-weight: bold !important; height: 55px !important; font-size: 1.1rem !important; border: none !important; width: 100% !important; border-radius: 8px !important;}
    """

st.markdown(f"""
    <style>
    .stApp {{ background-color: #fcfcfc !important; }}
    
    /* Configuración Dinámica de Solapas */
    {css_tabs}
    
    /* Input Boxes Estilizadas */
    .stTextArea textarea, .stFileUploader {{ 
        background-color: #eafaf1 !important; color: #111111 !important; 
        border: 2px solid #008a45 !important; border-radius: 8px !important;
    }}
    
    /* Botones de acción general */
    div.stButton > button:not([key^="tab_"]):not([key^="radio_"]) {{ 
        background-color: #008a45 !important; color: #ffffff !important; 
        font-weight: bold; border-radius: 8px !important; border: none !important;
        padding: 0.6rem 1.2rem; font-size: 1rem;
    }}
    
    /* CONTENEDORES DE SEMÁFORO REDISEÑADOS CON COLORES ENFÁTICOS */
    .caja-resultado {{ padding: 22px; border-radius: 12px; margin-top: 20px; margin-bottom: 20px; }}
    
    /* ROJO: Alto Impacto y Alerta Máxima */
    .resultado-rojo {{ 
        background-color: #fff1f0 !important; 
        border: 2px solid #ff4d4f !important; 
        border-left: 12px solid #ff4d4f !important; 
        box-shadow: 0 4px 14px rgba(255, 77, 79, 0.2);
        color: #1a0001 !important;
    }}
    
    /* AMARILLO: Moderado y Sutil */
    .resultado-amarillo {{ 
        background-color: #fffbe6 !important; 
        border: 1px solid #ffe58f !important; 
        border-left: 8px solid #faad14 !important; 
        color: #261a00 !important;
    }}
    
    /* VERDE: Mínimo impacto para acoplarse con la estética de la app */
    .resultado-verde {{ 
        background-color: #f9fbf9 !important; 
        border: 1px solid #e2ebd9 !important; 
        border-left: 5px solid #52c41a !important; 
        color: #444444 !important;
    }}
    
    /* Bloque Técnico Consola Forense Minimalista e Integrado */
    .metrica-forense {{ 
        font-family: inherit !important; 
        font-size: 0.95rem; 
        background-color: #fcfcfc !important; 
        padding: 5px 0px; 
        color: #334155 !important; 
        line-height: 1.6; 
    }}
    .bloque-linea {{
        padding: 8px 0;
        border-bottom: 1px solid #f1f5f9;
    }}
    .bloque-linea:last-child {{
        border-bottom: none;
    }}
    </style>
    """, unsafe_allow_html=True)

# ==============================================================================
# 4. MÓDULOS DE INFRAESTRUCTURA FORENSE AVANZADA Y APIS
# ==============================================================================
def limpiar_errores_ocr(t):
    t = re.sub(r'(\b[a-zA-Z0-9-]+)\s*\.\s*([a-zA-Z0-9.-]+)', r'\1.\2', t) 
    t = re.sub(r'\bw\s*\.\s*w\s*\.\s*w\b', 'www', t, flags=re.IGNORECASE)   
    t = re.sub(r'\bww\s*\.\s*w\b', 'www', t, flags=re.IGNORECASE)           
    t = re.sub(r'\bw\s*\.\s*ww\b', 'www', t, flags=re.IGNORECASE)           
    return t

def optimizar_traduccion_google(texto):
    if not texto or not texto.strip():
        return ""
    try:
        url = "https://translate.googleapis.com/translate_a/single"
        params = {"client": "gtx", "sl": "auto", "tl": "es", "dt": "t", "q": texto}
        response = requests.get(url, params=params, timeout=6).json()
        if response and response[0]:
            bloques_texto = [linea[0] for linea in response[0] if linea[0]]
            return "".join(bloques_texto)
    except: pass
    return texto

def procesar_imagen_ocr(archivo):
    try:
        if OCR_API_KEY == "PRUEBA_OCR_FREE_KEY":
            # Modo Simulación Académica si no hay Key Real
            return "Atención: detectamos actividad inusual en su perfil de instagram.com. Ingrese a www.soporte-seguridad-instagram.com para resolver."
        url = "https://api.ocr.space/parse/image"
        files = {'file': archivo}
        payload = {'apikey': OCR_API_KEY, 'language': 'spa', 'isOverlayRequired': False}
        res = requests.post(url, files=files, data=payload, timeout=15).json()
        if res.get("ParsedResults"): 
            return res["ParsedResults"][0]["ParsedText"]
        return None
    except: return None

def expandir_url(url_corta):
    try:
        response = requests.head(url_corta, allow_redirects=True, timeout=5)
        return response.url
    except: return url_corta

def analizar_infraestructura_completa(dominio):
    dns_info = {"ip": "No disponible", "alias": []}
    geo_info = {}
    try:
        ip = socket.gethostbyname(dominio)
        dns_info["ip"] = ip
        try:
            dns_info["alias"] = socket.gethostbyaddr(ip)[0]
        except: pass
        geo_data = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5).json()
        if not geo_data.get("error"):
            geo_info = geo_data
    except: pass
    return dns_info, geo_info

def auditar_whois_profundo(dominio):
    try:
        dom_base = dominio
        partes = dominio.split('.')
        if len(partes) > 2 and partes[0] in ['www', 'w', 'ww']:
            dom_base = ".".join(partes[1:])
        w = whois.whois(dom_base)
        return {
            "registrar": w.get("registrar"),
            "creation_date": w.get("creation_date"),
            "expiration_date": w.get("expiration_date"),
            "country": w.get("country"),
            "org": w.get("org")
        }
    except: return None

def auditar_ssl(dominio):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=dominio) as s:
            s.settimeout(5)
            s.connect((dominio, 443))
            return True, s.getpeercert()
    except Exception as e: return False, str(e)

@st.cache_data(ttl=3600)
def consultar_apis_reputacion_completa(url_analizada):
    res_final = {
        "google_match": False, "google_detalles": "Sin alertas registradas",
        "vt_maliciosos": 0, "vt_stats": {}
    }
    # Validación o Simulación para demostración académica segura
    if "PRUEBA" in GOOGLE_API_KEY or "PRUEBA" in VT_API_KEY:
        if "instagram.com" in url_analizada.lower() or "facebook.com" in url_analizada.lower():
            res_final["vt_maliciosos"] = 1  # Forzamos reporte positivo aislado para probar mitigación
            res_final["vt_stats"] = {"malicious": 1, "suspicious": 0, "harmless": 70}
        elif "anses" in url_analizada.lower() and "gob.ar" not in url_analizada.lower():
            res_final["google_match"] = True
            res_final["google_detalles"] = "Alerta de INGENIERÍA SOCIAL (Phishing) detectada por Google Safe Browsing."
            res_final["vt_maliciosos"] = 4
            res_final["vt_stats"] = {"malicious": 4, "suspicious": 1, "harmless": 68}
        return res_final

    # Implementación real de Google Safe Browsing API v4
    try:
        url_google = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        payload = {
            "client": {"clientId": "escudo-mayor", "clientVersion": "3.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url_analizada}]
            }
        }
        res_g = requests.post(url_google, json=payload, timeout=5).json()
        if "matches" in res_g:
            res_final["google_match"] = True
            res_final["google_detalles"] = f"Alerta Oficial de {res_g['matches'][0]['threatType']} detectada."
    except: pass

    # Implementación real de VirusTotal API v3
    try:
        url_id = base64.urlsafe_b64encode(url_analizada.encode()).decode().strip("=")
        res_v = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": VT_API_KEY}, timeout=5).json()
        stats = res_v.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        res_final["vt_maliciosos"] = stats.get('malicious', 0)
        res_final["vt_stats"] = stats
    except: pass
    
    return res_final

@st.cache_data(ttl=3600)
def buscar_osint_fraude_detallado(dominio):
    # Modo de pruebas / Simulación si faltan las variables OSINT avanzadas de Google Search
    if not GOOGLE_SEARCH_API_KEY or not GOOGLE_CX:
        if "link-checking" in dominio or "checking" in dominio:
            return 2, ["Reporte de estafa masiva simulando home banking.", "Denuncia en redes de suplantación de ANSES."]
        return 0, []
    try:
        url = f"https://www.googleapis.com/customsearch/v1?q=estafa+fraude+phishing+{dominio}&key={GOOGLE_SEARCH_API_KEY}&cx={GOOGLE_CX}"
        res = requests.get(url, timeout=5).json()
        total = int(res.get("searchInformation", {}).get("totalResults", "0"))
        items = res.get("items", [])
        return total, [i.get("snippet") for i in items[:2]]
    except: return 0, []

# ==============================================================================
# 5. MOTOR DE CORRELACIÓN DE INTELIGENCIA UNIFICADO Y NUEVO SEMÁFORO
# ==============================================================================
def ejecutar_analisis(texto_crudo):
    st.info("⏳ Iniciando correlación de vectores de amenaza y telemetría analítica...")
    
    texto_limpio = limpiar_errores_ocr(texto_crudo)
    texto_original = texto_limpio
    
    # Motor de Traducción Nativo Google por HTTP
    texto_traducido = optimizar_traduccion_google(texto_limpio)
    hubo_traduccion = False
    texto_analizar = texto_limpio
    
    if texto_traducido and texto_traducido.strip().lower() != texto_limpio.strip().lower():
        texto_analizar = texto_traducido
        hubo_traduccion = True

    # Regex corporativos
    urls_completas = re.findall(r'(https?://[^\s]+)', texto_analizar)
    dominios_sueltos = re.findall(r'\b(?:[a-zA-Z0-9](?:[-a-zA-Z0-9]*[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,6})\b', texto_analizar)
    emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', texto_analizar)
    telefonos = re.findall(r'(?:\+54\s?9\s?)?(?:11|[23]\d{2})\s?\d{4}[\-\s]?\d{4}', texto_analizar) 
    
    motivo_riesgo = []
    log_forense = [
        f"Fecha y Hora de la Auditoría: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
    ]
    
    # Flags operativos para el Semáforo
    api_positiva_detectada = False
    sitio_informado_phishing = False
    algo_sospechoso = False
    es_sitio_confianza = False
    sitio_evaluado_name = ""

    if emails:
        log_forense.append(f"Direcciones de Correo Detectadas: {', '.join(emails)}")
        motivo_riesgo.append(f"📧 **Remitente o dirección sospechosa:** {', '.join(emails)}")
        algo_sospechoso = True
    if telefonos:
        log_forense.append(f"Canales Telefónicos Extraídos: {', '.join(telefonos)}")
        motivo_riesgo.append(f"📱 **Línea de contacto telefónico no verificada:** {', '.join(telefonos)}")
        algo_sospechoso = True

    # Filtrar palabras clave unificadas
    palabras_encontradas = [p for p in PALABRAS_PELIGRO + PALABRAS_ALERTA if p in texto_analizar.lower()]
    cuenta_palabras = len(set(palabras_encontradas))
    
    if cuenta_palabras > 0:
        palabras_str = ", ".join(set(palabras_encontradas))
        log_forense.append(f"Coincidencia de Palabras Clave ({cuenta_palabras}): {palabras_str}")
        motivo_riesgo.append(f"🛑 **Indicadores de Manipulación:** Uso de términos de presión o alerta (*{palabras_str}*).")

    # Consolidación de entidades de red
    dominios_a_analizar = set()
    for u in urls_completas:
        dominios_a_analizar.add(urlparse(expandir_url(u.strip(".,!?\"'"))).netloc)
    for dom in dominios_sueltos:
        if dom.lower() not in ['png', 'jpg', 'jpeg', 'pdf', 'txt', 'html']:
            dominios_a_analizar.add(dom.lower())
    for email in emails:
        dominios_a_analizar.add(email.split('@')[-1])

    # Pipeline Forense de Dominios
    if dominios_a_analizar:
        for dom in dominios_a_analizar:
            log_forense.append(f"Escaneo Estructural de Dominio: {dom}")
            
            # Evaluación perimetral de Whitelist de Redes Sociales / Sitios de Confianza
            if any(confianza in dom for confianza in SITIOS_CONFIANZA_GLOBAL):
                es_sitio_confianza = True
                sitio_evaluado_name = dom

            # Detección de Typosquatting
            for marca in MARCAS_OFICIALES:
                if 0.75 < SequenceMatcher(None, dom, marca).ratio() < 1.0:
                    algo_sospechoso = True
                    log_forense.append(f"Análisis Léxico detectó Typosquatting con la entidad oficial: {marca}")
                    motivo_riesgo.append(f"🎭 **Intento de Suplantación Falsa:** El dominio `{dom}` es peligrosamente similar a la web legítima `{marca}`.")
                    break

            # DNS e Infraestructura
            dns_info, geo_info = analizar_infraestructura_completa(dom)
            log_forense.append(f"DNS Pasivo - IP de Destino: {dns_info['ip']} ({geo_info.get('country_name', 'Ubicación Distribuida/Oculta')})")
            
            # WHOIS Deep Audit
            w_datos = auditar_whois_profundo(dom)
            if w_datos and isinstance(w_datos, dict):
                fc = w_datos.get('creation_date')
                if isinstance(fc, list) and len(fc) > 0: fc = fc[0]
                if fc and isinstance(fc, datetime):
                    antiguedad = (datetime.now() - fc.replace(tzinfo=None)).days
                    log_forense.append(f"WHOIS Audit - Antigüedad del registro: {antiguedad} días")
                    if antiguedad < 30:
                        algo_sospechoso = True
                        motivo_riesgo.append(f"⏱️ **Infraestructura de Creación Inmediata:** El sitio web fue creado hace menos de un mes ({antiguedad} días).")

            # Auditoría SSL
            ssl_valido, ssl_detalles = auditar_ssl(dom)
            log_forense.append(f"SSL/TLS Integrity Check: {'Válido' if ssl_valido else 'Falla/Ausente - ' + str(ssl_detalles)}")

            # CONSULTA EXPLICITA A APIS DE REPUTACIÓN GLOBALES
            rep = consultar_apis_reputacion_completa(dom)
            log_forense.append(f"Google Safe Browsing Match: {rep['google_match']} ({rep['google_detalles']})")
            log_forense.append(f"VirusTotal Detections: {rep['vt_maliciosos']} motores positivos")
            
            if rep["google_match"] or rep["vt_maliciosos"] > 0:
                api_positiva_detectada = True
                if not es_sitio_confianza:
                    motivo_riesgo.append(f"🚨 **Lista Negra Técnica:** Reportado formalmente en bases de datos mundiales de Phishing/Malware.")

            # Módulo OSINT de Reputación
            total_osint, fragmentos = buscar_osint_fraude_detallado(dom)
            log_forense.append(f"Menciones públicas de estafa indexadas en Google: {total_osint}")
            if total_osint > 0:
                if not es_sitio_confianza:
                    sitio_informado_phishing = True
                    motivo_riesgo.append(f"🔍 **Historial de Denuncias Públicas:** Registra alertas previas indexadas en motores de búsqueda vinculadas a estafas.")

    # ==============================================================================
    # 6. REESTRUCTURACIÓN DE LOGICA DEL SEMÁFORO INTELIGENTE Y ALERTAS
    # ==============================================================================
    if es_sitio_confianza:
        color_veredicto = "amarillo"
        motivo_riesgo = [
            f"✨ **Plataforma Verificada:** El enlace apunta a una aplicación real y legítima (`{sitio_evaluado_name}`). No está bloqueada.",
            "⚠️ **¡Cuidado con perfiles engañosos!** Aunque la infraestructura de la red social es de confianza, recuerde que los estafadores suelen crear cuentas o perfiles falsos dentro de Instagram o Facebook para mandar mensajes simulando ser empresas o parientes."
        ]
    else:
        if api_positiva_detectada or sitio_informado_phishing or algo_sospechoso or (cuenta_palabras >= 3):
            color_veredicto = "rojo"
        elif (1 <= cuenta_palabras <= 2) and not (api_positiva_detectada or sitio_informado_phishing or algo_sospechoso):
            color_veredicto = "amarillo"
        else:
            color_veredicto = "verde"
    
    # Inyección de HTML dinámico según la categoría del Semáforo Reestructurado
    razones_html = "".join([f"<li>{m}</li>" for m in set(motivo_riesgo)]) if motivo_riesgo else "<li>No hay alertas técnicas automáticas activas en los diccionarios conceptuales.</li>"

    if color_veredicto == "rojo":
        st.markdown(f"""
        <div class="caja-resultado resultado-rojo">
            <h2 style="color: #d32f2f; margin-top:0; font-size:1.5rem; font-weight:800;">🔴 PELIGRO CRÍTICO DETECTADO</h2>
            <p style="font-size: 1.05rem;"><b>Se recomienda interrumpir de inmediato cualquier tipo de comunicación o ingreso de contraseñas. Los sistemas de ciberdefensa confirman un vector de ataque activo o altamente peligroso.</b></p>
            <ul style="margin-top: 10px; line-height: 1.5;">{razones_html}</ul>
        </div>
        """, unsafe_allow_html=True)
    elif color_veredicto == "amarillo":
        st.markdown(f"""
        <div class="caja-resultado resultado-amarillo">
            <h2 style="color: #d46b08; margin-top:0; font-size:1.4rem; font-weight:700;">🟡 PRECAUCIÓN RECOMENDADA</h2>
            <p><b>Mensaje o plataforma bajo análisis con intenciones dudosas basadas en patrones aislados. Valide siempre la veracidad del perfil antes de responder.</b></p>
            <ul style="margin-top: 10px;">{razones_html}</ul>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="caja-resultado resultado-verde">
            <h2 style="color: #389e0d; margin-top:0; font-size:1.25rem; font-weight:700;">🟢 SEGURO / SIN ANOMALÍAS AUTOMÁTICAS</h2>
            <p style="font-size: 0.95rem; margin-bottom: 0;">El análisis automatizado no encontró registros maliciosos o de riesgo evidente. Recuerde que las instituciones oficiales jamás le exigirán contraseñas ni códigos de seguridad.</p>
        </div>
        """, unsafe_allow_html=True)

    # ==============================================================================
    # DESPLIEGUE DESDUPLICADO DE RESULTADOS DE TEXTO (UNA SOLA VEZ)
    # ==============================================================================
    st.write("---")
    if hubo_traduccion:
        st.text_area("📝 Contenido Analizado (Traducción al Español de Seguridad):", value=texto_analizar, height=120, key=f"disp_trad_{random.randint(1,9999)}")
        with st.expander("Ver Texto en Idioma Original Recibido", expanded=False):
            st.text(texto_original)
    else:
        st.text_area("📝 Mensaje Bajo Análisis Técnico:", value=texto_original, height=120, key=f"disp_orig_{random.randint(1,9999)}")

    # Despliegue de Consola Forense Avanzada (Diseño Ultra-Compacto y Agrupado por Jerarquía)
    with st.expander("🛠️ Ver Reporte Forense Completo de Infraestructura (Consola Técnica)", expanded=False):
        html_lineas = []
        es_primer_dominio = True
        
        for item in log_forense:
            # Detectar inicio de un nuevo contexto de dominio
            if "Escaneo Estructural de Dominio" in item:
                margin_top = "0px" if es_primer_dominio else "10px"
                border_top = "none" if es_primer_dominio else "1px dashed #e2e8f0"
                es_primer_dominio = False
                
                html_lineas.append(
                    f"<div style='margin-top: {margin_top}; padding-top: 5px; border-top: {border_top}; font-weight: 700; color: #008a45; font-size: 0.95rem; line-height: 1.2;'>🌐 {item}</div>"
                )
            # Detectar metadatos globales del análisis inicial
            elif any(header in item for header in ["Fecha y Hora", "Coincidencia de Palabras", "Direcciones de Correo", "Canales Telefónicos"]):
                html_lineas.append(
                    f"<div style='padding: 1px 0; font-weight: 600; color: #1e293b; font-size: 0.95rem; line-height: 1.2;'>📋 {item}</div>"
                )
            # Métricas anidadas dependientes del dominio bajo inspección
            else:
                html_lineas.append(
                    f"<div style='padding: 0.5px 0; padding-left: 18px; font-size: 0.88rem; color: #475569; line-height: 1.2;'>• {item}</div>"
                )
        
        # Renderizado final con herencia tipográfica limpia del sistema de la app
        st.markdown(f"""
        <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif !important; background-color: #fcfcfc; padding: 2px 0;">
            {"".join(html_lineas)}
        </div>
        """, unsafe_allow_html=True)

# ==============================================================================
# 7. INTERFAZ DE USUARIO CONSOLIDADA (CUSTOM TABS SIN TEXTO DUPLICADO)
# ==============================================================================
col_tab1, col_tab2 = st.columns(2)

with col_tab1:
    if st.button("Analizar Imagen", use_container_width=True, key="tab_imagen_btn"):
        st.session_state["active_tab"] = "imagen"
        st.rerun()

with col_tab2:
    if st.button("Analizar Texto", use_container_width=True, key="tab_texto_btn"):
        st.session_state["active_tab"] = "texto"
        st.rerun()

st.write("") 

# Bloques de Entrada Aislados sin Impresión Espejo Auxiliar
if st.session_state["active_tab"] == "imagen":
    st.markdown("**Suba una captura de pantalla o foto del mensaje:**")
    archivo = st.file_uploader("", type=["png", "jpg", "jpeg"], key="uploader_automatizado")
    
    if archivo is not None:
        file_id = f"{archivo.name}_{archivo.size}"
        if st.session_state.get("last_processed_file_id") != file_id:
            with st.spinner("Procesando lectura óptica forense instantánea..."):
                texto_ocr = procesar_imagen_ocr(archivo)
                st.session_state["stored_text_ocr"] = texto_ocr
                st.session_state["last_processed_file_id"] = file_id
        
        if st.session_state.get("stored_text_ocr"):
            ejecutar_analisis(st.session_state["stored_text_ocr"])
        elif st.session_state.get("stored_text_ocr") == "":
            st.error("No se detectó texto procesable dentro de la captura provista.")
else:
    texto_ingresado = st.text_area(
        label="**Pegue o escriba el mensaje, correo o link sospechoso a evaluar:**", 
        height=140, 
        placeholder="Ejemplo: Ingrese el texto del SMS o la dirección web extraña...", 
        key="input_consola_manual"
    )
    if st.button("🔍 Iniciar Análisis de Texto", use_container_width=True):
        if texto_ingresado.strip(): 
            ejecutar_analisis(texto_ingresado)
        else:
            st.warning("Por favor, ingrese contenido de texto antes de ejecutar el análisis.")

# ==============================================================================
# 8. MÓDULO INTERACTIVO DE TRIVIA DIARIA
# ==============================================================================
st.write("---")

if "pregunta_actual" not in st.session_state:
    st.session_state.pregunta_actual = random.choice(TRIVIA_SEGURIDAD)
    st.session_state.respondido = False
    st.session_state.opcion_elegida = None

with st.container(border=True):
    st.markdown("<h4 style='color: #008a45; margin-top:0;'>🧠 Desafío Diario de Seguridad</h4>", unsafe_allow_html=True)
    q = st.session_state.pregunta_actual
    st.write(f"**{q['pregunta']}**")
    
    opcion = st.radio("Seleccione la opción correcta:", q['opciones'], key="radio_trivia_secure")
    
    col_v1, col_v2 = st.columns([1, 1])
    with col_v1:
        if st.button("✅ Verificar Respuesta", use_container_width=True):
            st.session_state.respondido = True
            st.session_state.opcion_elegida = opcion
            
    with col_v2:
        if st.session_state.respondido:
            if st.button("⏭️ Siguiente Desafío", use_container_width=True):
                st.session_state.pregunta_actual = random.choice(TRIVIA_SEGURIDAD)
                st.session_state.respondido = False
                st.rerun()

    if st.session_state.respondido:
        if st.session_state.opcion_elegida == q['respuesta']:
            st.success(f"**¡Correcto!** {q['explicacion']}")
        else:
            st.error(f"**Atención:** La opción correcta era **{q['respuesta']}**. {q['explicacion']}")

# ==============================================================================
# 9. REFUERZO OPERATIVO Y DESCARGOS LEGALES ACADÉMICOS
# ==============================================================================
st.write("---")
with st.container(border=True):
    st.markdown("""
    💡 <b>RECORDATORIO:</b> Ningún organismo, banco, empresa de servicios, obra social o prepaga te pedirá claves o tokens por mensaje. Ante cualquier duda contactate través de los canales oficiales.
     """, unsafe_allow_html=True)

st.markdown('<p style="font-size: 0.75rem; color: #718096; text-align: center; margin-top: 15px;">🛡️ Entorno Académico de Simulación Forense - Licenciatura en Seguridad Informática - Universidad Siglo 21.</p>', unsafe_allow_html=True)
