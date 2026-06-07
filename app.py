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

# Módulo de traducción para campañas internacionales
try:
    from deep_translator import GoogleTranslator
except ImportError:
    GoogleTranslator = None

# Importar Trivia
try:
    from preguntas import TRIVIA_SEGURIDAD
except ImportError:
    TRIVIA_SEGURIDAD = [{"pregunta": "¿El banco te pide claves por WhatsApp?", "opciones": ["Sí", "No"], "respuesta": "No", "explicacion": "Ningún banco pide contraseñas por WhatsApp."}]

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
    .block-container { padding-top: 1.5rem !important; }
    h1, h2, h3 { color: #008a45 !important; font-weight: 800; text-align: center; margin-bottom: 0.5rem !important; }
    
    /* Reparación del Uploader: Ocultar textos e íconos por defecto que causan solapamiento */
    [data-testid="stFileUploadDropzone"] div div::before { display: none !important; content: "" !important; }
    [data-testid="stFileUploadDropzone"] svg { display: none !important; }
    
    /* Reparación del Expander (flecha) */
    .st-expander summary p { font-weight: bold !important; font-size: 1.1rem !important; }
    
    /* Semáforos más compactos e informativos */
    .caja-resultado { padding: 15px !important; border-radius: 8px; margin-top: 10px !important; margin-bottom: 20px !important;}
    .resultado-rojo { background-color: #fee2e2 !important; border-left: 10px solid #dc2626 !important; color: #991b1b !important; }
    .resultado-amarillo { background-color: #fef3c7 !important; border-left: 10px solid #d97706 !important; color: #92400e !important; }
    .resultado-verde { background-color: #dcfce7 !important; border-left: 10px solid #16a34a !important; color: #166534 !important; }
    
    .metrica-forense { font-family: sans-serif !important; font-size: 0.9rem; background-color: #f8fafc; padding: 15px; border-radius: 5px; }
    .metrica-forense ul { margin-top: 5px; margin-bottom: 5px; }
    .metrica-forense li { margin-bottom: 8px; }
    
    /* Contenedor de la Trivia */
    .caja-trivia { border: 2px solid #e2e8f0; border-radius: 8px; padding: 15px; background-color: #f1f8f5; margin-top: 30px; margin-bottom: 20px;}
    </style>
    """, unsafe_allow_html=True)

st.markdown("<h1>🛡️ Escudo Mayor</h1>", unsafe_allow_html=True)
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

def auditar_ssl(dominio):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=dominio) as s:
            s.settimeout(5)
            s.connect((dominio, 443))
            cert = s.getpeercert()
            return True if cert else False
    except: return False

@st.cache_data(ttl=3600)
def consultar_apis_reputacion(url_analizada):
    try:
        GOOGLE_API_KEY = st.secrets["GOOGLE_API_KEY"]
        VT_API_KEY = st.secrets["VT_API_KEY"]
        
        # Consultar SafeBrowsing
        url_google = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        res_g = requests.post(url_google, json={"client": {"clientId": "escudo", "clientVersion": "1.0"}, "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url_analizada}]}}).json()
        en_google = "matches" in res_g

        # Consultar VirusTotal
        url_id = base64.urlsafe_b64encode(url_analizada.encode()).decode().strip("=")
        res_v = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": VT_API_KEY}).json()
        vt_malicious = res_v.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
        
        return en_google, vt_malicious > 0
    except: return False, False

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
def ejecutar_analisis(texto_crudo):
    
    # 5.0 TRADUCCIÓN AUTOMÁTICA
    texto = texto_crudo
    if GoogleTranslator:
        try:
            texto = GoogleTranslator(source='auto', target='es').translate(texto_crudo)
        except:
            pass # Si falla el traductor, usamos el original

    urls = re.findall(r'(https?://[^\s]+)', texto)
    emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', texto)
    telefonos = re.findall(r'(?:\+54\s?9\s?)?(?:11|[23]\d{2})\s?\d{4}[\-\s]?\d{4}', texto) 
    
    riesgo_critico = False
    motivo_riesgo = []
    
    log_forense = []
    log_forense.append("**[*] INICIANDO PIPELINE FORENSE DE ESCUDO MAYOR**")
    map_data = None
    
    # 5A. Análisis de Textos y Patrones
    if emails:
        log_forense.append(f"* **Correos detectados:** {', '.join(emails)}")
        motivo_riesgo.append(f"📧 **Correo sospechoso detectado:** {', '.join(emails)}")
    if telefonos:
        log_forense.append(f"* **Teléfonos detectados:** {', '.join(telefonos)}")
        motivo_riesgo.append(f"📱 **Teléfono detectado:** {', '.join(telefonos)} (No contactar).")

    palabras_encontradas = [p for p in PALABRAS_PELIGRO + PALABRAS_ALERTA if p in texto.lower()]
    
    if palabras_encontradas:
        palabras_str = ", ".join(set(palabras_encontradas))
        motivo_riesgo.append(f"🛑 **Palabras de manipulación detectadas:** {palabras_str}.")
        log_forense.append(f"* **Coincidencia en Blacklist:** {palabras_str}")
        if any(p in texto.lower() for p in PALABRAS_PELIGRO):
            riesgo_critico = True
    
    # 5B. Análisis de Infraestructura
    dominios_a_analizar = set()
    if urls:
        for u in urls:
            url_f = expandir_url(u.strip(".,!?\"'"))
            log_forense.append(f"* **URL Detectada:** {u}")
            if url_f != u:
                log_forense.append(f"* **URL Expandida (Destino real):** {url_f}")
            dominios_a_analizar.add(urlparse(url_f).netloc)
    
    for email in emails:
        dominios_a_analizar.add(email.split('@')[-1])

    if dominios_a_analizar:
        log_forense.append("\n**[+] AUDITORÍA DE INFRAESTRUCTURA DETALLADA:**")
        for dom in dominios_a_analizar:
            log_forense.append(f"\n**--- Analizando Dominio: {dom} ---**")
            
            # 1. Typosquatting
            try:
                for marca in MARCAS_OFICIALES:
                    if 0.75 < SequenceMatcher(None, dom, marca).ratio() < 1.0:
                        riesgo_critico = True
                        log_forense.append(f"* ⚠️ **TYPOSQUATTING:** Intento de suplantación de {marca}")
                        motivo_riesgo.append(f"🎭 **Suplantación de Identidad:** El enlace se hace pasar por **{marca}**.")
                        break
            except Exception as e: log_forense.append(f"* ❌ Error Typosquatting: {e}")

            # 2. Reputación
            try:
                en_google, en_vt = consultar_apis_reputacion(dom)
                if en_google or en_vt:
                    riesgo_critico = True
                    log_forense.append(f"* ⚠️ **REPUTACIÓN:** Malicioso (Google Safe: {en_google}, VirusTotal: {en_vt})")
                    if en_vt: motivo_riesgo.append(f"🦠 **VirusTotal:** Reporta que el enlace ({dom}) contiene software malicioso o fraude.")
                    if en_google: motivo_riesgo.append(f"🚨 **Google Safe Browsing:** Marcó este sitio ({dom}) como página engañosa/phishing.")
                else: log_forense.append("* ✅ **REPUTACIÓN:** Dominio limpio en bases de datos.")
            except Exception as e: log_forense.append(f"* ❌ Error Reputación: {e}")
            
            # 3. WHOIS
            try:
                dias = auditar_whois(dom)
                if dias is not None:
                    log_forense.append(f"* 🕒 **WHOIS (Antigüedad):** Creado hace {dias} días.")
                    if dias < 30:
                        riesgo_critico = True
                        log_forense.append(f"* ⚠️ **ALERTA WHOIS:** Infraestructura extremadamente reciente ({dias} días).")
                        motivo_riesgo.append(f"⏱️ **Página Reciente:** La página fue creada hace apenas {dias} días. Es una táctica común para estafas efímeras.")
                else: log_forense.append("* 🕒 **WHOIS:** No se pudo obtener la fecha de creación.")
            except Exception as e: log_forense.append(f"* ❌ Error WHOIS: {e}")

            # 4. Certificado SSL
            try:
                if auditar_ssl(dom):
                    log_forense.append("* 🔒 **CERTIFICADO SSL:** Válido y activo.")
                else:
                    log_forense.append("* 🔓 **CERTIFICADO SSL:** Inválido o inexistente.")
            except Exception as e: log_forense.append(f"* ❌ Error SSL: {e}")

            # 5. DNS & Geolocalización
            try:
                ip, geo = analizar_infraestructura(dom)
                if ip:
                    log_forense.append(f"* 🌍 **DNS a IP:** Resuelve a la IP {ip}")
                    if geo and not geo.get("error"):
                        log_forense.append(f"* 📍 **GEOLOCALIZACIÓN:** {geo.get('city')}, {geo.get('region')}, {geo.get('country_name')} (ISP: {geo.get('org')})")
                        map_data = pd.DataFrame({'lat': [geo.get('latitude')], 'lon': [geo.get('longitude')]})
                else: log_forense.append("* 🌍 **DNS:** No se pudo resolver la IP.")
            except Exception as e: log_forense.append(f"* ❌ Error DNS/GEO: {e}")

            # 6. OSINT Google Search
            try:
                if buscar_osint_fraude(dom):
                    log_forense.append(f"* 🔍 **OSINT GOOGLE:** Se encontraron reportes públicos de fraude asociados a {dom}.")
                    motivo_riesgo.append(f"🕵️ **Reportes Públicos:** Hay denuncias de estafa en internet relacionadas a **{dom}**.")
                else: log_forense.append("* 🔍 **OSINT GOOGLE:** Sin resultados negativos en foros públicos.")
            except Exception as e: log_forense.append(f"* ❌ Error OSINT: {e}")
                
    # ==============================================================================
    # 6. RENDERIZADO VISUAL DEL SEMÁFORO
    # ==============================================================================
    if motivo_riesgo:
        razones_html = "".join([f"<li>{motivo}</li>" for motivo in set(motivo_riesgo)])
    else:
        razones_html = "<li>El mensaje parece ser un texto normal sin enlaces ni números peligrosos detectables.</li>"

    if riesgo_critico or (urls and palabras_encontradas):
        st.markdown(f"""
        <div class="caja-resultado resultado-rojo">
            <h2 style="font-size: 1.3rem; color: #991b1b !important;">🔴 ALERTA DE PELIGRO EXTREMO</h2>
            <p><strong>Corte toda comunicación. Su dinero o sus datos están en riesgo.</strong></p>
            <p>Motivos encontrados:</p>
            <ul style="font-size: 0.95rem;">{razones_html}</ul>
        </div>
        """, unsafe_allow_html=True)
    elif palabras_encontradas or telefonos or emails:
        st.markdown(f"""
        <div class="caja-resultado resultado-amarillo">
            <h2 style="font-size: 1.3rem; color: #92400e !important;">🟡 PRECAUCIÓN RECOMENDADA</h2>
            <p><strong>Hemos detectado tácticas de manipulación en el texto.</strong></p>
            <p>Hallazgos:</p>
            <ul style="font-size: 0.95rem;">{razones_html}</ul>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="caja-resultado resultado-verde">
            <h2 style="font-size: 1.3rem; color: #166534 !important;">🟢 MENSAJE SIN ALERTAS CLARAS</h2>
            <p style="font-size: 0.95rem;">El sistema no detectó enlaces maliciosos ni lenguaje extorsivo. De todos modos, nunca comparta códigos ni transfiera dinero a desconocidos.</p>
        </div>
        """, unsafe_allow_html=True)

    # ==============================================================================
    # 7. CONSOLA TÉCNICA Y TEXTO EXTRAÍDO
    # ==============================================================================
    st.write("---")
    st.markdown("### 📝 Texto detectado (Traducido y analizado):")
    st.info(texto)

    log_texto_final = "\n".join(log_forense)
    
    # Se remueve el ícono de tuerca del título para que no colisione con la flecha de Streamlit
    with st.expander("Reporte Forense Detallado de Infraestructura", expanded=False):
        st.markdown(f"<div class='metrica-forense'>{log_texto_final}</div>", unsafe_allow_html=True)
        if map_data is not None and not map_data.isnull().values.any():
            st.write("**Atribución Geográfica del Atacante:**")
            st.map(map_data, zoom=3)

# ==============================================================================
# 8. PESTAÑAS Y FLUJO PRINCIPAL (INTERFAZ DE ESCÁNER)
# ==============================================================================
tab1, tab2 = st.tabs(["📸 Revisar Imagen", "✍️ Escribir Mensaje"])

with tab1:
    st.markdown("**Suba la captura de pantalla de su celular aquí:**")
    archivo = st.file_uploader(" ", type=["png", "jpg", "jpeg"], label_visibility="collapsed")
    
    if archivo is not None:
        with st.spinner("Escaneando imagen, traduciendo y analizando texto..."):
            texto_ext = procesar_imagen_ocr(archivo)
            if texto_ext and texto_ext.strip():
                ejecutar_analisis(texto_ext)
            else:
                st.error("Error al leer la imagen. Intente con una captura más nítida.")

with tab2:
    st.markdown("**Mantenga apretado y pegue el mensaje sospechoso:**")
    texto_ingresado = st.text_area("Texto", height=150, label_visibility="collapsed")
    
    if st.button("🔍 Revisar Texto", use_container_width=True):
        if texto_ingresado.strip(): 
            ejecutar_analisis(texto_ingresado)

# ==============================================================================
# 9. SISTEMA DE TRIVIA DIARIA (DESAFÍO AL FINAL)
# ==============================================================================
st.write("---")
if "pregunta_actual" not in st.session_state:
    st.session_state.pregunta_actual = random.choice(TRIVIA_SEGURIDAD)
    st.session_state.respondido = False
    st.session_state.opcion_elegida = None

st.markdown("<div class='caja-trivia'>", unsafe_allow_html=True)
st.markdown("<h4 style='color: #008a45; text-align: left;'>🧠 Reto de Seguridad</h4>", unsafe_allow_html=True)
q = st.session_state.pregunta_actual
st.write(f"**{q['pregunta']}**")

opcion = st.radio("Seleccione su respuesta:", q['opciones'], key="radio_trivia", label_visibility="collapsed")

col1, col2 = st.columns([1, 1])
with col1:
    if st.button("✅ Comprobar respuesta", use_container_width=True):
        st.session_state.respondido = True
        st.session_state.opcion_elegida = opcion

with col2:
    if st.session_state.respondido:
        if st.button("⏭️ Siguiente Reto", use_container_width=True):
            st.session_state.pregunta_actual = random.choice(TRIVIA_SEGURIDAD)
            st.session_state.respondido = False
            st.rerun()

if st.session_state.respondido:
    if st.session_state.opcion_elegida == q['respuesta']:
        st.success(f"**¡Correcto!** {q['explicacion']}")
    else:
        st.error(f"**Incorrecto.** La respuesta correcta era: **{q['respuesta']}**. {q['explicacion']}")
st.markdown("</div>", unsafe_allow_html=True)

# ==============================================================================
# 10. AVISOS LEGALES Y RECORDATORIOS
# ==============================================================================
st.markdown("""
<div style="background-color: #f4f4f4; padding: 15px; border-radius: 8px; border-left: 5px solid #008a45; margin-bottom: 20px;">
    💡 <b>RECORDATORIO VITAL:</b> Ningún organismo (ANSES, PAMI), banco o empresa le pedirá claves, tokens o CBU por mensaje. Ante la duda, corte y llame a los números oficiales.
</div>
""", unsafe_allow_html=True)

st.caption("🛡️ Escudo Mayor es una aplicación con fines educativos e informativos para la protección digital. No está diseñada para uso comercial.")
