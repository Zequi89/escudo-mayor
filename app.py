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
    h1, h2, h3, .titulo-siglo21 { color: #008a45 !important; font-weight: 800; text-align: center; }
    p, li { font-size: 1.1rem; line-height: 1.6; }
    .stTextArea textarea, .stFileUploader { border: 2px solid #008a45 !important; border-radius: 8px; font-size: 1.1rem; }
    div.stButton > button { background-color: #008a45 !important; color: #ffffff !important; font-weight: bold; border-radius: 8px !important; width: 100%; padding: 12px; font-size: 1.2rem; }
    
    /* Cajas de Resultado */
    .caja-resultado { padding: 20px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-top: 20px; }
    .resultado-rojo { background-color: #ffcccc; border-left: 12px solid #cc0000; color: #111;}
    .resultado-amarillo { background-color: #fff2cc; border-left: 12px solid #d4aa00; color: #111;}
    .resultado-verde { background-color: #d5f5e3; border-left: 12px solid #008a45; color: #111;}
    
    /* Panel Forense Integrado (Claro y limpio) */
    .metrica-forense { 
        font-family: monospace; 
        font-size: 0.95rem; 
        background-color: #f4f6f5; 
        color: #2b2b2b; 
        padding: 20px; 
        border-radius: 8px; 
        margin-top: 10px; 
        border: 1px solid #dcdcdc;
        line-height: 1.5;
        white-space: pre-wrap;
    }
    .metrica-forense b { color: #008a45; }
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
    st.info("⏳ Analizando los datos. Un momento por favor...")
    
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
    
    # 5B. Análisis de Infraestructura (URLs)
    if urls:
        url_original = urls[0].strip(".,!?\"'")
        url_final = expandir_url(url_original)
        dominio = urlparse(url_final).netloc
        
        log_forense += f"\n<b>[+] AUDITORÍA DE ENLACES:</b>\n"
        log_forense += f"  - Original: {url_original}\n  - Desofuscado: {url_final}\n  - Dominio base: {dominio}\n\n"
        
        # Typosquatting
        for marca in MARCAS_OFICIALES:
            if 0.75 < SequenceMatcher(None, dominio, marca).ratio() < 1.0:
                riesgo_critico = True
                log_forense += f"[!] TYPOSQUATTING: Simula ser {marca}\n"
                motivo_riesgo.append(f"El enlace es falso e intenta hacerse pasar por <b>{marca}</b>.")
                break

        # Reputación
        if consultar_apis_reputacion(url_final):
            riesgo_critico = True
            log_forense += "[!] REPUTACIÓN: Dominio reportado en Safe Browsing / VirusTotal.\n"
            motivo_riesgo.append("Nuestros motores de seguridad confirmaron que el enlace contiene virus o estafas.")
            
        # WHOIS (Antigüedad)
        dias_vida = auditar_whois(dominio)
        if dias_vida is not None:
            log_forense += f"[+] WHOIS: Dominio registrado hace {dias_vida} días.\n"
            if dias_vida < 30:
                riesgo_critico = True
                log_forense += "[!] ALERTA WHOIS: Infraestructura temporal detectada.\n"
                motivo_riesgo.append(f"La página web fue creada hace apenas {dias_vida} días (muy habitual en fraudes).")
                
        # DNS & Geolocalización
        ip, geo = analizar_infraestructura(dominio)
        if ip:
            log_forense += f"[+] RESOLUCIÓN DNS: {dominio} -> {ip}\n"
            if geo and not geo.get("error"):
                log_forense += f"[+] GEO-IP: {geo.get('city')}, {geo.get('country_name')} (ISP: {geo.get('org')})\n"
                map_data = pd.DataFrame({'lat': [geo.get('latitude')], 'lon': [geo.get('longitude')]})

        # OSINT Google
        if buscar_osint_fraude(dominio):
            log_forense += "[!] OSINT: Existen reportes públicos de fraude sobre este dominio.\n"

    # ==============================================================================
    # 6. RENDERIZADO VISUAL DEL SEMÁFORO
    # ==============================================================================
    if riesgo_critico or (urls and palabras_encontradas):
        razones_html = "".join([f"<li>{motivo}</li>" for motivo in set(motivo_riesgo)]) if motivo_riesgo else "<li>El enlace ha sido reportado como peligroso.</li>"
        st.markdown(f"""
        <div class="caja-resultado resultado-rojo">
            <h2 style="color: #cc0000; margin-top: 0;">🔴 ¡ALERTA DE PELIGRO!</h2>
            <p><b>No haga clic en ningún enlace ni responda este mensaje.</b></p>
            <p>Hemos encontrado problemas graves en su mensaje:</p>
            <ul>{razones_html}</ul>
            <p><i>Corte la comunicación y contacte a su entidad por canales oficiales.</i></p>
        </div>
        """, unsafe_allow_html=True)
    elif palabras_encontradas or telefonos or emails:
        razones_html = "".join([f"<li>{motivo}</li>" for motivo in set(motivo_riesgo)])
        st.markdown(f"""
        <div class="caja-resultado resultado-amarillo">
            <h2 style="color: #b38600; margin-top: 0;">🟡 PRECAUCIÓN</h2>
            <p>Este mensaje tiene elementos sospechosos:</p>
            <ul>{razones_html}</ul>
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
    st.markdown("**Suba la captura de pantalla de su celular aquí:**")
    archivo = st.file_uploader("", type=["png", "jpg", "jpeg"], label_visibility="collapsed")
    
    if archivo is not None and st.button("👁️ Analizar Imagen"):
        with st.spinner("Nuestra IA está extrayendo los datos..."):
            texto_ext = procesar_imagen_ocr(archivo)
            
            if texto_ext and texto_ext.strip():
                st.success("Lectura exitosa. Analizando el contenido...")
                st.text_area("Contenido extraído:", value=texto_ext, height=120, disabled=True)
                ejecutar_analisis(texto_ext)
            else:
                st.error("Hubo un error leyendo la imagen. Intente pegar el texto manualmente.")

with tab2:
    st.markdown("**Mantenga apretado y pegue el mensaje sospechoso:**")
    texto_ingresado = st.text_area("", height=150, label_visibility="collapsed")
    
    if st.button("🔍 Revisar Texto"):
        if texto_ingresado.strip(): 
            ejecutar_analisis(texto_ingresado)

st.write("---")
st.markdown("""
<div style="background-color: #f4f4f4; padding: 15px; border-radius: 8px; border-left: 5px solid #008a45;">
    <b>💡 RECORDÁ:</b><br>
    Ningún organismo, banco, empresa de servicios, obra social o prepaga te pedirá claves o tokens por mensaje. 
    Ante cualquier duda, cortá la comunicación y contactate siempre a través de los canales oficiales.
</div>
""", unsafe_allow_html=True)
