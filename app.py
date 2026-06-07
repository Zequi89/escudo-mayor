# ==============================================================================
# 1. IMPORTACIONES Y CONFIGURACIÓN INICIAL
# ==============================================================================
import streamlit as st
import requests
import re
import base64
import socket
import whois
import pandas as pd
from datetime import datetime
from urllib.parse import urlparse
from difflib import SequenceMatcher

# Configuración de la página
st.set_page_config(page_title="Escudo Mayor", page_icon="🛡️", layout="centered")

# ==============================================================================
# 2. DICCIONARIOS Y CONSTANTES DE SEGURIDAD
# ==============================================================================
try:
    from blacklist import PALABRAS_PELIGRO, PALABRAS_ALERTA
except ImportError:
    PALABRAS_PELIGRO = ['transferencia', 'bloqueada', 'urgente', 'cbu', 'token', 'embargo', 'suspendida']
    PALABRAS_ALERTA = ['premio', 'ganador', 'sorteo', 'vencimiento', 'validar', 'oferta']

MARCAS_OFICIALES = [
    'anses.gob.ar', 'bna.com.ar', 'bancoprovincia.com.ar', 
    'galicia.com.ar', 'macro.com.ar', 'santander.com.ar',
    'netflix.com', 'mercadolibre.com.ar', 'mercadopago.com.ar', 'pami.org.ar'
]

# ==============================================================================
# 3. ESTILOS VISUALES (CSS FRONT-END)
# ==============================================================================
st.markdown("""
    <style>
    /* Tipografía universal */
    html, body, [class*="st-"] { font-family: sans-serif !important; }
    
    /* Título más arriba (ajuste de margen negativo) */
    .block-container { padding-top: 1rem !important; }
    h1, h2, h3 { color: #008a45 !important; font-weight: 800; text-align: center; margin-bottom: 0.5rem !important; }
    
    /* Semáforos más compactos */
    .caja-resultado { padding: 15px !important; border-radius: 8px; margin-top: 10px !important; }
    
    /* Alerta visual mejorada */
    .resultado-rojo { background-color: #fee2e2 !important; border-left: 10px solid #dc2626 !important; color: #991b1b !important; }
    .resultado-amarillo { background-color: #fef3c7 !important; border-left: 10px solid #d97706 !important; color: #92400e !important; }
    .resultado-verde { background-color: #dcfce7 !important; border-left: 10px solid #16a34a !important; color: #166534 !important; }
    
    .metrica-forense { font-family: sans-serif !important; font-size: 0.9rem; background-color: #f8fafc; padding: 10px; border-radius: 5px; }
</style>
    """, unsafe_allow_html=True)

st.markdown("<h1 class='titulo-siglo21'>🛡️ Escudo Mayor</h1>", unsafe_allow_html=True)
st.markdown("<h3>Protección Digital para Adultos Mayores</h3>", unsafe_allow_html=True)

# ==============================================================================
# 4. MÓDULOS DEL PIPELINE FORENSE (BACK-END)
# ==============================================================================
def procesar_imagen_ocr(archivo):
    try:
        url = "https://api.ocr.space/parse/image"
        files = {'file': archivo}
        payload = {'apikey': st.secrets["OCR_API_KEY"], 'language': 'spa', 'isOverlayRequired': False}
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

def analizar_infraestructura(dominio):
    try:
        ip = socket.gethostbyname(dominio)
        geo_data = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5).json()
        return ip, geo_data
    except: return None, None

def auditar_whois(dominio):
    try:
        w = whois.whois(dominio)
        fecha_creacion = w.creation_date
        if isinstance(fecha_creacion, list): fecha_creacion = fecha_creacion[0]
        if fecha_creacion: return (datetime.now() - fecha_creacion).days
        return None
    except: return None

@st.cache_data(ttl=3600)
def consultar_apis_reputacion(url_analizada):
    try:
        GOOGLE_API_KEY = st.secrets["GOOGLE_API_KEY"]
        VT_API_KEY = st.secrets["VT_API_KEY"]
        riesgo = False
        
        url_google = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        res_g = requests.post(url_google, json={"client": {"clientId": "escudo", "clientVersion": "1.0"}, "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url_analizada}]}}).json()
        
        url_id = base64.urlsafe_b64encode(url_analizada.encode()).decode().strip("=")
        res_v = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": VT_API_KEY}).json()
        vt_malicious = res_v.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
        
        if "matches" in res_g or vt_malicious > 0: riesgo = True
        return riesgo
    except: return False

@st.cache_data(ttl=3600)
def buscar_osint_fraude(dominio):
    try:
        api_key = st.secrets.get("GOOGLE_SEARCH_API_KEY")
        cx = st.secrets.get("GOOGLE_CX")
        if not api_key or not cx: return False
        url = f"https://www.googleapis.com/customsearch/v1?q=estafa+fraude+phishing+{dominio}&key={api_key}&cx={cx}"
        res = requests.get(url, timeout=5).json()
        return int(res.get("searchInformation", {}).get("totalResults", "0")) > 0
    except: return False

# ==============================================================================
# 5. MOTOR DE CORRELACIÓN HEURÍSTICA (NÚCLEO)
# ==============================================================================
def ejecutar_analisis(texto):
    
    urls = re.findall(r'(https?://[^\s]+)', texto)
    emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', texto)
    telefonos = re.findall(r'(?:\+54\s?9\s?)?(?:11|[23]\d{2})\s?\d{4}[\-\s]?\d{4}', texto) 
    
    riesgo_critico = False
    motivo_riesgo = []
    log_forense = "<b>[*] INICIANDO PIPELINE FORENSE DE ESCUDO MAYOR</b>\n\n"
    map_data = None
    
    # 5A. Análisis de Textos y Patrones
    if emails:
        log_forense += f"[+] Correos detectados: {', '.join(emails)}\n"
        motivo_riesgo.append(f"El mensaje contiene un correo electrónico sospechoso: {', '.join(emails)}")
    if telefonos:
        log_forense += f"[+] Teléfonos detectados: {', '.join(telefonos)}\n"
        motivo_riesgo.append(f"Se detectó un número telefónico. No llame ni escriba: {', '.join(telefonos)}")

    # Detección exacta de palabras de la Blacklist
    palabras_encontradas = [p for p in PALABRAS_PELIGRO + PALABRAS_ALERTA if p in texto.lower()]
    
    if palabras_encontradas:
        # Se agregan al motivo para que aparezcan en el semáforo
        palabras_str = ", ".join(set(palabras_encontradas))
        motivo_riesgo.append(f"Detectamos palabras de alerta frecuentes en engaños: <b>{palabras_str}</b>.")
        log_forense += f"[!] Coincidencia en Blacklist: {palabras_str}\n"
        
        # Si alguna es de peligro alto, se marca como crítico
        if any(p in texto.lower() for p in PALABRAS_PELIGRO):
            riesgo_critico = True
    
    # 5B. Análisis de Infraestructura (Forzamos ejecución siempre)
    dominios_a_analizar = set()
    if urls:
        for u in urls:
            url_f = expandir_url(u.strip(".,!?\"'"))
            dominios_a_analizar.add(urlparse(url_f).netloc)
    
    for email in emails:
        dominios_a_analizar.add(email.split('@')[-1])

    if dominios_a_analizar:
        log_forense += f"\n<b>[+] AUDITORÍA DE INFRAESTRUCTURA:</b>\n"
        for dom in dominios_a_analizar:
            log_forense += f"\n--- Analizando: {dom} ---\n"
            
            # 1. Typosquatting
            try:
                for marca in MARCAS_OFICIALES:
                    if 0.75 < SequenceMatcher(None, dom, marca).ratio() < 1.0:
                        riesgo_critico = True
                        log_forense += f"[!] TYPOSQUATTING: Suplantación de {marca}\n"
                        motivo_riesgo.append(f"El dominio <b>{dom}</b> intenta suplantar a <b>{marca}</b>.")
                        break
            except Exception as e: log_forense += f"[!] Error Typosquatting: {e}\n"

            # 2. Reputación
            try:
                if consultar_apis_reputacion(dom):
                    riesgo_critico = True
                    log_forense += "[!] REPUTACIÓN: Dominio reportado como malicioso.\n"
                    motivo_riesgo.append(f"El dominio {dom} tiene reportes de actividad maliciosa.")
            except Exception as e: log_forense += f"[!] Error Reputación: {e}\n"
            
            # 3. WHOIS
            try:
                dias = auditar_whois(dom)
                if dias is not None:
                    log_forense += f"[+] WHOIS: Dominio creado hace {dias} días.\n"
                    if dias < 30:
                        riesgo_critico = True
                        log_forense += f"[!] ALERTA WHOIS: Infraestructura temporal ({dias} días).\n"
                        motivo_riesgo.append(f"El dominio {dom} es muy reciente.")
                else: log_forense += "[+] WHOIS: No se pudo obtener antigüedad.\n"
            except Exception as e: log_forense += f"[!] Error WHOIS: {e}\n"

            # 4. DNS & Geolocalización
            try:
                ip, geo = analizar_infraestructura(dom)
                if ip:
                    log_forense += f"[+] DNS: {dom} -> {ip}\n"
                    if geo and not geo.get("error"):
                        log_forense += f"[+] GEO: {geo.get('city')}, {geo.get('country_name')}\n"
                        map_data = pd.DataFrame({'lat': [geo.get('latitude')], 'lon': [geo.get('longitude')]})
                else: log_forense += "[+] DNS: No se pudo resolver.\n"
            except Exception as e: log_forense += f"[!] Error DNS/GEO: {e}\n"

            # 5. OSINT Google Search
            try:
                if buscar_osint_fraude(dom):
                    log_forense += f"[!] OSINT: Reportes de fraude encontrados para {dom}.\n"
                    motivo_riesgo.append(f"Existen reportes públicos de fraude asociados a <b>{dom}</b>.")
                else: log_forense += "[+] OSINT: Sin resultados públicos negativos.\n"
            except Exception as e: log_forense += f"[!] Error OSINT: {e}\n"
                
    # ==============================================================================
    # 6. RENDERIZADO VISUAL DEL SEMÁFORO
    # ==============================================================================
    # Construcción de razones primero para evitar el NameError
    if motivo_riesgo:
        razones_html = "".join([f"<li>{motivo}</li>" for motivo in set(motivo_riesgo)])
    else:
        razones_html = "<li>El mensaje contiene elementos inusuales.</li>"

    if riesgo_critico or (urls and palabras_encontradas):
        st.markdown(f"""
        <div class="caja-resultado resultado-rojo">
            <h2 style="font-size: 1.2rem; color: #991b1b !important;">🔴 ALERTA DE PELIGRO</h2>
            <ul style="font-size: 0.9rem;">{razones_html}</ul>
        </div>
        """, unsafe_allow_html=True)
    elif palabras_encontradas or telefonos or emails:
        st.markdown(f"""
        <div class="caja-resultado resultado-amarillo">
            <h2 style="font-size: 1.2rem; color: #92400e !important;">🟡 PRECAUCIÓN</h2>
            <ul style="font-size: 0.9rem;">{razones_html}</ul>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="caja-resultado resultado-verde">
            <h2 style="font-size: 1.2rem; color: #166534 !important;">🟢 MENSAJE SIN ALERTAS</h2>
            <p style="font-size: 0.9rem;">No se detectaron amenazas inmediatas.</p>
        </div>
        """, unsafe_allow_html=True)

    # ==============================================================================
    # 7. CONSOLA TÉCNICA (DEFENSA UNIVERSITARIA)
    # ==============================================================================
    if log_forense != "<b>[*] INICIANDO PIPELINE FORENSE DE ESCUDO MAYOR</b>\n\n":
        st.write("---")
        with st.expander("⚙️ Ver Reporte Forense Detallado"):
            st.markdown(f"<div class='metrica-forense'>{log_forense}</div>", unsafe_allow_html=True)
            if map_data is not None and not map_data.isnull().values.any():
                st.write("**Atribución de Infraestructura Atacante:**")
                st.map(map_data, zoom=3)

# ==============================================================================
# 8. PESTAÑAS Y FLUJO PRINCIPAL
# ==============================================================================
tab1, tab2 = st.tabs(["📸 Revisar Imagen", "✍️ Escribir Mensaje"])

with tab1:
    # Usamos session_state para que la app no pierda el estado de la imagen
    if "imagen_analizada" not in st.session_state:
        st.session_state.imagen_analizada = None

    st.markdown("**Suba la captura de pantalla de su celular aquí:**")
    archivo = st.file_uploader("Subir", type=["png", "jpg", "jpeg"], label_visibility="collapsed")
    
    if archivo is not None:
        # Solo procesamos si el archivo es nuevo
        with st.spinner("Procesando..."):
            texto_ext = procesar_imagen_ocr(archivo)
            if texto_ext and texto_ext.strip():
                ejecutar_analisis(texto_ext)
            else:
                st.error("Error al leer la imagen. Intente con una más clara.")
    
    if st.button("Limpiar Imagen"):
        st.rerun()

with tab2:
    st.markdown("**Mantenga apretado y pegue el mensaje sospechoso:**")
    texto_ingresado = st.text_area("Texto", height=150, label_visibility="collapsed")
    
    if st.button("🔍 Revisar Texto"):
        if texto_ingresado.strip(): 
            ejecutar_analisis(texto_ingresado)

st.write("---")
st.markdown("""
<div style="background-color: #f4f4f4; padding: 15px; border-radius: 8px; border-left: 5px solid #008a45;">
    💡 <b>RECORDÁ:</b> Ningún organismo, banco, empresa de servicios, obra social o prepaga te pedirá claves o tokens por mensaje. Ante cualquier duda, cortá la comunicación y contactate siempre a través de los canales oficiales.
</div>
""", unsafe_allow_html=True)
