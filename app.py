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

# Configuración de la página (Debe ser la primera instrucción de Streamlit)
st.set_page_config(page_title="Escudo Mayor", page_icon="🛡️", layout="centered")

# ==============================================================================
# 2. DICCIONARIOS Y CONSTANTES DE SEGURIDAD
# ==============================================================================
# Fallback de seguridad en caso de que el archivo blacklist.py no esté disponible
try:
    from blacklist import PALABRAS_PELIGRO, PALABRAS_ALERTA
except ImportError:
    PALABRAS_PELIGRO = ['transferencia', 'bloqueada', 'urgente', 'cbu', 'token', 'embargo', 'suspendida']
    PALABRAS_ALERTA = ['premio', 'ganador', 'sorteo', 'vencimiento', 'validar', 'oferta']

# Marcas utilizadas para detectar ataques de Typosquatting (dominios visualmente similares)
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
    h1, h2, h3, .titulo-siglo21 { color: #008a45 !important; font-weight: 800; text-align: center; }
    p, li { font-size: 1.1rem; line-height: 1.6; }
    .stTextArea textarea, .stFileUploader { border: 2px solid #008a45 !important; border-radius: 8px; font-size: 1.1rem; }
    div.stButton > button { background-color: #008a45 !important; color: #ffffff !important; font-weight: bold; border-radius: 8px !important; width: 100%; padding: 12px; font-size: 1.2rem; }
    .caja-resultado { padding: 20px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-top: 20px; }
    .resultado-rojo { background-color: #ffcccc; border-left: 12px solid #cc0000; color: #111;}
    .resultado-amarillo { background-color: #fff2cc; border-left: 12px solid #d4aa00; color: #111;}
    .resultado-verde { background-color: #d5f5e3; border-left: 12px solid #008a45; color: #111;}
    .metrica-forense { font-family: monospace; font-size: 0.85rem; background: #1e1e1e; color: #00ff00; padding: 15px; border-radius: 8px; margin-top: 10px; overflow-x: auto; border: 1px solid #333;}
    </style>
    """, unsafe_allow_html=True)

st.markdown("<h1 class='titulo-siglo21'>🛡️ Escudo Mayor</h1>", unsafe_allow_html=True)
st.markdown("<h3>Protección Digital para Adultos Mayores</h3>", unsafe_allow_html=True)

# ==============================================================================
# 4. MÓDULOS DEL PIPELINE FORENSE (BACK-END)
# ==============================================================================
def procesar_imagen_ocr(archivo):
    """Extrae texto de imágenes usando la API de OCR.space."""
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
    """Resuelve redirecciones de URLs acortadas de forma segura."""
    try:
        response = requests.head(url_corta, allow_redirects=True, timeout=5)
        return response.url
    except: return url_corta

def analizar_infraestructura(dominio):
    """Resuelve la IP del dominio y obtiene su geolocalización."""
    try:
        ip = socket.gethostbyname(dominio)
        geo_data = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5).json()
        return ip, geo_data
    except: return None, None

def auditar_whois(dominio):
    """Obtiene la antigüedad del dominio en días."""
    try:
        w = whois.whois(dominio)
        fecha_creacion = w.creation_date
        if isinstance(fecha_creacion, list): fecha_creacion = fecha_creacion[0]
        if fecha_creacion: return (datetime.now() - fecha_creacion).days
        return None
    except: return None

@st.cache_data(ttl=3600)
def consultar_apis_reputacion(url_analizada):
    """Consulta bases de datos de amenazas (Google Safe Browsing y VirusTotal). Usa caché para no gastar cuota."""
    try:
        GOOGLE_API_KEY = st.secrets["GOOGLE_API_KEY"]
        VT_API_KEY = st.secrets["VT_API_KEY"]
        riesgo = False
        
        # Google Safe Browsing
        url_google = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        res_g = requests.post(url_google, json={"client": {"clientId": "escudo", "clientVersion": "1.0"}, "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url_analizada}]}}).json()
        
        # VirusTotal
        url_id = base64.urlsafe_b64encode(url_analizada.encode()).decode().strip("=")
        res_v = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": VT_API_KEY}).json()
        vt_malicious = res_v.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
        
        if "matches" in res_g or vt_malicious > 0: riesgo = True
        return riesgo
    except: return False

@st.cache_data(ttl=3600)
def buscar_osint_fraude(dominio):
    """Busca reportes de fraude en la web usando Google Custom Search API."""
    try:
        api_key = st.secrets.get("GOOGLE_SEARCH_API_KEY")
        cx = st.secrets.get("GOOGLE_CX")
        if not api_key or not cx: return False
        url = f"https://www.googleapis.com/customsearch/v1?q=estafa+fraude+phishing+{dominio}&key={api_key}&cx={cx}"
        res = requests.get(url, timeout=5).json()
        return int(res.get("searchInformation", {}).get("totalResults", "0")) > 0
    except: return False

# ==============================================================================
# 5. MOTOR DE CORRELACIÓN HEURÍSTICA (NÚCLEO DEL PROGRAMA)
# ==============================================================================
def ejecutar_analisis(texto):
    st.info("⏳ Revisando el mensaje por su seguridad...")
    
    # Expresiones regulares para extracción de datos clave
    urls = re.findall(r'(https?://[^\s]+)', texto)
    emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', texto)
    telefonos = re.findall(r'(?:\+54\s?9\s?)?(?:11|[23]\d{2})\s?\d{4}[\-\s]?\d{4}', texto) 
    
    riesgo_critico = False
    motivo_riesgo = []
    log_forense = "[*] INICIANDO PIPELINE FORENSE DE ESCUDO MAYOR\n\n"
    map_data = None
    
    # 5A. Análisis de Textos y Patrones
    if emails:
        log_forense += f"[+] Correos detectados: {', '.join(emails)}\n"
        motivo_riesgo.append("El mensaje contiene un correo electrónico sospechoso.")
    if telefonos:
        log_forense += f"[+] Teléfonos detectados: {', '.join(telefonos)}\n"
        motivo_riesgo.append("El mensaje incluye un número telefónico. No llame ni envíe WhatsApp a ese número.")

    puntaje_texto = sum([1 for p in PALABRAS_PELIGRO if p in texto.lower()])
    if puntaje_texto >= 1:
        riesgo_critico = True
        motivo_riesgo.append("Detectamos palabras usadas frecuentemente en estafas bancarias.")
    
    # 5B. Análisis de Infraestructura (Si hay URLs)
    if urls:
        url_original = urls[0].strip(".,!?\"'")
        url_final = expandir_url(url_original)
        dominio = urlparse(url_final).netloc
        
        log_forense += f"[+] Enlace Original: {url_original}\n[+] Destino Final: {url_final}\n[+] Dominio a auditar: {dominio}\n\n"
        
        # Typosquatting
        for marca in MARCAS_OFICIALES:
            if 0.75 < SequenceMatcher(None, dominio, marca).ratio() < 1.0:
                riesgo_critico = True
                log_forense += f"[!] TYPOSQUATTING: Simula ser {marca}\n"
                motivo_riesgo.append(f"El enlace es falso e intenta hacerse pasar por {marca}.")
                break

        # Reputación
        if consultar_apis_reputacion(url_final):
            riesgo_critico = True
            log_forense += "[!] REPUTACIÓN: Marcado como MALICIOSO (VirusTotal/Google).\n"
            
        # WHOIS (Antigüedad)
        dias_vida = auditar_whois(dominio)
        if dias_vida is not None:
            log_forense += f"[+] WHOIS: Edad del dominio -> {dias_vida} días.\n"
            if dias_vida < 30:
                riesgo_critico = True
                log_forense += "[!] ALERTA WHOIS: Infraestructura temporal (Phishing).\n"
                motivo_riesgo.append("La página web fue creada hace muy pocos días para realizar estafas.")
                
        # DNS & Geolocalización
        ip, geo = analizar_infraestructura(dominio)
        if ip:
            log_forense += f"[+] RESOLUCIÓN DNS: {dominio} -> {ip}\n"
            if geo and not geo.get("error"):
                log_forense += f"[+] GEO-IP: {geo.get('city')}, {geo.get('country_name')} (ISP: {geo.get('org')})\n"
                map_data = pd.DataFrame({'lat': [geo.get('latitude')], 'lon': [geo.get('longitude')]})

        # Búsqueda OSINT
        if buscar_osint_fraude(dominio):
            log_forense += "[!] OSINT: Hay reportes de fraude asociados a este dominio en Google.\n"

    # ==============================================================================
    # 6. RENDERIZADO VISUAL (INTERFAZ PARA EL USUARIO MAYOR)
    # ==============================================================================
    if riesgo_critico or (urls and puntaje_texto > 0):
        razones_html = "".join([f"<li>{motivo}</li>" for motivo in set(motivo_riesgo)]) if motivo_riesgo else "<li>El enlace ha sido reportado como peligroso.</li>"
        st.markdown(f"""
        <div class="caja-resultado resultado-rojo">
            <h2 style="color: #cc0000; margin-top: 0;">🔴 ¡ALERTA DE PELIGRO!</h2>
            <p><b>No haga clic en ningún enlace ni responda este mensaje.</b></p>
            <p>Hemos encontrado problemas graves:</p>
            <ul>{razones_html}</ul>
            <p><i>Si tiene dudas sobre su cuenta, comuníquese con su banco usando el número que figura detrás de su tarjeta.</i></p>
        </div>
        """, unsafe_allow_html=True)
    elif puntaje_texto > 0 or telefonos or emails:
        st.markdown("""
        <div class="caja-resultado resultado-amarillo">
            <h2 style="color: #b38600; margin-top: 0;">🟡 PRECAUCIÓN</h2>
            <p>Este mensaje tiene elementos sospechosos (números de contacto o palabras de alerta).</p>
            <p>Recuerde: <b>Las entidades oficiales no piden transferencias ni tokens por WhatsApp.</b></p>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="caja-resultado resultado-verde">
            <h2 style="color: #008a45; margin-top: 0;">🟢 MENSAJE SIN ALERTAS</h2>
            <p>No hemos detectado infraestructura maliciosa, pero <b>mantenga siempre la precaución</b>.</p>
        </div>
        """, unsafe_allow_html=True)

    # ==============================================================================
    # 7. CONSOLA TÉCNICA AVANZADA (PARA DEFENSA DEL PROYECTO)
    # ==============================================================================
    if log_forense:
        st.write("---")
        with st.expander("⚙️ Mostrar Análisis Técnico Profundo"):
            st.markdown(f"<div class='metrica-forense'><pre>{log_forense}</pre></div>", unsafe_allow_html=True)
            if map_data is not None and not map_data.isnull().values.any():
                st.write("**Atribución de Infraestructura Atacante:**")
                st.map(map_data, zoom=3)

# ==============================================================================
# 8. ESTRUCTURA DE PESTAÑAS Y FLUJO PRINCIPAL
# ==============================================================================
tab1, tab2 = st.tabs(["📸 Revisar Imagen", "✍️ Escribir Mensaje"])

with tab1:
    st.markdown("**Suba la captura de pantalla de su celular aquí:**")
    archivo = st.file_uploader("", type=["png", "jpg", "jpeg"], label_visibility="collapsed")
    
    if archivo is not None and st.button("👁️ Analizar Imagen"):
        with st.spinner("Nuestra IA está extrayendo los datos..."):
            texto_ext = procesar_imagen_ocr(archivo)
            
            if texto_ext and texto_ext.strip():
                # El texto se muestra inmediatamente después de procesar
                st.success("Lectura exitosa. Analizando el siguiente contenido:")
                st.text_area("Contenido extraído:", value=texto_ext, height=120, disabled=True)
                ejecutar_analisis(texto_ext)
            else:
                st.error("No logramos detectar texto o hubo un error en la conexión. Intente pegar el texto manualmente en la otra pestaña.")

with tab2:
    st.markdown("**Mantenga apretado y pegue el mensaje sospechoso:**")
    texto_ingresado = st.text_area("", height=150, label_visibility="collapsed")
    
    if st.button("🔍 Revisar Texto"):
        if texto_ingresado.strip(): 
            ejecutar_analisis(texto_ingresado)

# Pie de página con consejos
st.write("---")
st.markdown("""
<div style="background-color: #f4f4f4; padding: 15px; border-radius: 8px;">
    <b>💡 CONSEJOS DE SEGURIDAD (Ministerio de Seguridad / ANSES):</b><br>
    • Ningún organismo público te va a pedir que vayas a un cajero automático.<br>
    • No compartas códigos de validación de WhatsApp con nadie.<br>
    • Los perfiles falsos en redes sociales suelen contactarte primero. Un banco legítimo no hace eso.
</div>
""", unsafe_allow_html=True)
