
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

# Importar Trivia desde archivo externo obligatorio
try:
    from preguntas import TRIVIA_SEGURIDAD
except ImportError:
    TRIVIA_SEGURIDAD = [
        {"pregunta": "¿El banco te pide claves por WhatsApp?", "opciones": ["Sí", "No"], "respuesta": "No", "explicacion": "Ningún banco pide contraseñas por WhatsApp."}
    ]

# Configuración de la página basada en el prototipo base
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
# 3. ESTILOS VISUALES UNIFICADOS (CSS PROTOTIPO)
# ==============================================================================
st.markdown("""
    <style>
    .stApp { background-color: #fcfcfc !important; }
    h1, h2, h3, .titulo-siglo21 { color: #008a45 !important; font-weight: bold; text-align: center; }
    
    /* Cajas de texto y uploader estilizadas según el prototipo */
    .stTextArea textarea, .stFileUploader { 
        background-color: #eafaf1 !important; color: #111111 !important; 
        border: 2px solid #008a45 !important; border-radius: 8px !important;
    }
    
    /* Botones estables sin colisión de margen */
    div.stButton > button { 
        background-color: #008a45 !important; color: #ffffff !important; 
        font-weight: bold; border-radius: 8px !important; border: none !important;
        padding: 0.5rem 1rem;
    }
    
    /* Contenedores de Semáforos */
    .caja-resultado { padding: 20px; border-radius: 8px; color: #111111 !important; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-top: 15px; margin-bottom: 15px; }
    .resultado-rojo { background-color: #ffcccc; border-left: 10px solid #cc0000; }
    .resultado-amarillo { background-color: #fff2cc; border-left: 10px solid #d4aa00; }
    .resultado-verde { background-color: #d5f5e3; border-left: 10px solid #008a45; }
    
    .metrica-forense { font-family: sans-serif !important; font-size: 0.9rem; background-color: #f8fafc; padding: 15px; border-radius: 5px; color: #111111; }
    </style>
    """, unsafe_allow_html=True)

st.markdown("<h1 class='titulo-siglo21'>🛡️ Escudo Mayor</h1>", unsafe_allow_html=True)
st.markdown("<h3 style='color: #555; font-size: 1.1rem;'>Fortalecimiento Digital para el Adulto Mayor</h3>", unsafe_allow_html=True)

# ==============================================================================
# 4. MÓDULOS DE INFRAESTRUCTURA FORENSE
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
        
        url_google = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        res_g = requests.post(url_google, json={"client": {"clientId": "escudo", "clientVersion": "1.0"}, "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url_analizada}]}}).json()
        en_google = "matches" in res_g

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
# 5. MOTOR DE CORRELACIÓN UNIFICADO (TEXTO E IMAGEN)
# ==============================================================================
def ejecutar_analisis(texto_crudo):
    st.info("⏳ Iniciando análisis exhaustivo de contenido y enlaces...")
    
    # Módulo de traducción seguro incorporado internamente
    texto = texto_crudo
    try:
        from deep_translator import GoogleTranslator
        texto_traducido = GoogleTranslator(source='auto', target='es').translate(texto_crudo)
        if texto_traducido:
            texto = texto_traducido
    except Exception:
        pass # Si no detecta conexión o servidor externo, procesa el texto plano de forma segura

    # Extracción inteligente de URLs completas y dominios sueltos (ej: facebook.com)
    urls_completas = re.findall(r'(https?://[^\s]+)', texto)
    dominios_sueltos = re.findall(r'\b(?:[a-zA-Z0-9](?:[-a-zA-Z0-9]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b', texto)
    emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', texto)
    telefonos = re.findall(r'(?:\+54\s?9\s?)?(?:11|[23]\d{2})\s?\d{4}[\-\s]?\d{4}', texto) 
    
    riesgo_critico = False
    motivo_riesgo = []
    log_forense = ["**[*] INICIANDO PIPELINE FORENSE DE ESCUDO MAYOR**"]
    map_data = None
    
    # Análisis de Textos y Patrones
    if emails:
        log_forense.append(f"* **Correos detectados:** {', '.join(emails)}")
        motivo_riesgo.append(f"📧 **Correo sospechoso detectado:** {', '.join(emails)}")
    if telefonos:
        log_forense.append(f"* **Teléfonos detectados:** {', '.join(telefonos)}")
        motivo_riesgo.append(f"📱 **Teléfono detectado:** {', '.join(telefonos)} (Verificar procedencia).")

    palabras_encontradas = [p for p in PALABRAS_PELIGRO + PALABRAS_ALERTA if p in texto.lower()]
    if palabras_encontradas:
        palabras_str = ", ".join(set(palabras_encontradas))
        motivo_riesgo.append(f"🛑 **Palabras de manipulación detectadas:** {palabras_str}.")
        log_forense.append(f"* **Coincidencia en Filtro Base:** {palabras_str}")
        if any(p in texto.lower() for p in PALABRAS_PELIGRO):
            riesgo_critico = True
    
    # Unificación de Dominios a analizar
    dominios_a_analizar = set()
    for u in urls_completas:
        url_f = expandir_url(u.strip(".,!?\"'"))
        log_forense.append(f"* **Enlace completo detectado:** {u}")
        dominios_a_analizar.add(urlparse(url_f).netloc)
        
    for dom in dominios_sueltos:
        if dom.lower() not in ['png', 'jpg', 'jpeg', 'pdf', 'txt']: # Excluir extensiones falsas
            dominios_a_analizar.add(dom.lower())
            
    for email in emails:
        dominios_a_analizar.add(email.split('@')[-1])

    # Auditoría de Infraestructura Unificada (Aplica tanto a links planos como texto ingresado)
    if dominios_a_analizar:
        log_forense.append("\n**[+] AUDITORÍA DE INFRAESTRUCTURA DETALLADA:**")
        for dom in dominios_a_analizar:
            log_forense.append(f"\n**--- Analizando Entidad: {dom} ---**")
            
            # 1. Suplantación de Identidad (Typosquatting)
            for marca in MARCAS_OFICIALES:
                if 0.75 < SequenceMatcher(None, dom, marca).ratio() < 1.0:
                    riesgo_critico = True
                    log_forense.append(f"* ⚠️ **ALERTA:** Similitud crítica sospechosa con {marca}")
                    motivo_riesgo.append(f"🎭 **Suplantación:** El dominio imita de forma engañosa a la entidad oficial **{marca}**.")
                    break

            # 2. Bases de Datos de Reputación
            en_google, en_vt = consultar_apis_reputacion(dom)
            if en_google or en_vt:
                riesgo_critico = True
                log_forense.append(f"* ⚠️ **REPUTACIÓN NEGATIVA:** (SafeBrowsing: {en_google}, VirusTotal: {en_vt})")
                if en_vt: motivo_riesgo.append(f"🦠 **Filtro Técnico:** Reportado en VirusTotal como sitio fraudulento.")
                if en_google: motivo_riesgo.append(f"🚨 **Google Safe:** Marcado de forma oficial como página engañosa.")
            
            # 3. Antigüedad WHOIS
            dias = auditar_whois(dom)
            if dias is not None:
                log_forense.append(f"* 🕒 **Antigüedad de registro:** {dias} días.")
                if dias < 30:
                    riesgo_critico = True
                    motivo_riesgo.append(f"⏱️ **Sitio Extrañamente Nuevo:** Esta dirección en internet fue creada hace solo {dias} días.")
            
            # 4. SSL, DNS y Geolocalización
            if auditar_ssl(dom): log_forense.append("* 🔒 **SSL:** Certificado válido presente.")
            ip, geo = analizar_infraestructura(dom)
            if ip:
                log_forense.append(f"* 🌍 **Resolución DNS:** Apunta a la IP {ip}")
                if geo and not geo.get("error"):
                    log_forense.append(f"* 📍 **Origen:** {geo.get('city')}, {geo.get('country_name')} ({geo.get('org')})")
                    map_data = pd.DataFrame({'lat': [geo.get('latitude')], 'lon': [geo.get('longitude')]})

            # 5. OSINT Crítico
            if buscar_osint_fraude(dom):
                motivo_riesgo.append(f"🔍 **Denuncias en Red:** Se detectaron foros públicos alertando fraudes asociados a `{dom}`.")
                
    # ==============================================================================
    # 6. MÓDULO VISUAL: SEMÁFORO INTELIGENTE
    # ==============================================================================
    if motivo_riesgo:
        razones_html = "".join([f"<li>{m}</li>" for m in set(motivo_riesgo)])
    else:
        razones_html = "<li>No se han detectado patrones de manipulación evidentes ni dominios de riesgo conocidos.</li>"

    if riesgo_critico or (urls_completas and palabras_encontradas):
        st.markdown(f"""
        <div class="caja-resultado resultado-rojo">
            <h2 style="color: #cc0000; margin-top:0;">🔴 ALERTA DE PELIGRO EXTREMO</h2>
            <p><b>Se recomienda interrumpir cualquier interacción. Sus activos o datos privados están comprometidos.</b></p>
            <ul>{razones_html}</ul>
        </div>
        """, unsafe_allow_html=True)
    elif palabras_encontradas or telefonos or emails:
        st.markdown(f"""
        <div class="caja-resultado resultado-amarillo">
            <h2 style="color: #b48600; margin-top:0;">🟡 PRECAUCIÓN RECOMENDADA</h2>
            <p><b>Mensaje con indicios sospechosos. Proceda con cuidado y valide la información.</b></p>
            <ul>{razones_html}</ul>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="caja-resultado resultado-verde">
            <h2 style="color: #008a45; margin-top:0;">🟢 PARECE SEGURO</h2>
            <p>El sistema no detectó anomalías automáticas. Manténgase alerta ante solicitudes inesperadas.</p>
        </div>
        """, unsafe_allow_html=True)

    # Box Editable para manipulación rápida del texto
    st.write("---")
    st.markdown("### 📝 Contenido bajo análisis (Editable/Copiable):")
    st.text_area("Texto recuperado del pipeline:", value=texto, height=120, key=f"edit_{random.randint(1,9999)}")

    # Reporte Forense Técnico en desplegable limpio
    with st.expander("Informe Forense Detallado", expanded=False):
        st.markdown(f"<div class='metrica-forense'>{'<br>'.join(log_forense).replace('\n', '<br>')}</div>", unsafe_allow_html=True)
        if map_data is not None and not map_data.isnull().values.any():
            st.write("**Ubicación Geográfica Estimada del Servidor:**")
            st.map(map_data, zoom=2)

# ==============================================================================
# 7. INTERFAZ DE USUARIO CONSOLIDADA (PESTAÑAS)
# ==============================================================================
tab1, tab2 = st.tabs(["📸 Analizar Imagen / Captura", "✍️ Analizar Texto Manual"])

with tab1:
    st.markdown("**Suba el archivo o captura de pantalla de su dispositivo móvil:**")
    archivo = st.file_uploader("", type=["png", "jpg", "jpeg"], key="uploader_principal")
    if archivo is not None:
        if st.button("👁️ Procesar Imagen e Iniciar Análisis", use_container_width=True):
            with st.spinner("Ejecutando OCR y descifrado forense..."):
                texto_ocr = procesar_imagen_ocr(archivo)
                if texto_ocr and texto_ocr.strip():
                    ejecutar_analisis(texto_ocr)
                else:
                    st.error("No se pudo extraer texto legible de la imagen suministrada.")

with tab2:
    st.markdown("**Pegue o escriba cualquier mensaje o dirección web sospechosa:**")
    texto_ingresado = st.text_area("", height=150, placeholder="Ejemplo: facebook.com o un mensaje de texto sospechoso...", key="input_consola")
    if st.button("🔍 Analizar Entrada de Texto", use_container_width=True):
        if texto_ingresado.strip(): 
            ejecutar_analisis(texto_ingresado)
        else:
            st.warning("Debe ingresar un texto o enlace válido para activar el motor.")

# ==============================================================================
# 8. MÓDULO INTERACTIVO DE TRIVIA (CONTENEDOR NATIVO SIN FILTRACIONES)
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
    
    col1, col2 = st.columns([1, 1])
    with col1:
        if st.button("✅ Verificar Respuesta", use_container_width=True):
            st.session_state.respondido = True
            st.session_state.opcion_elegida = opcion
            
    with col2:
        if st.session_state.respondido:
            if st.button("⏭️ Siguiente Desafío", use_container_width=True):
                st.session_state.pregunta_actual = random.choice(TRIVIA_SEGURIDAD)
                st.session_state.respondido = False
                st.rerun()

    if st.session_state.respondido:
        if st.session_state.opcion_elegida == q['respuesta']:
            st.success(f"**¡Correcto!** {q['explicacion']}")
        else:
            st.error(f"**Atención:** La respuesta sugerida era **{q['respuesta']}**. {q['explicacion']}")

# ==============================================================================
# 9. MARCO LEGAL Y RECORDATORIO OPERATIVO
# ==============================================================================
st.write("---")
with st.container(border=True):
    st.markdown("""
    💡 <b>RECORDATORIO VITAL DE SEGURIDAD:</b> Ningún organismo gubernamental (como ANSES o PAMI), entidad bancaria privada ni prestador de servicios legítimo le solicitará claves secretas, tokens de seguridad o transferencias de dinero mediante canales informales. Ante cualquier duda, interrumpa el contacto.
    """, unsafe_allow_html=True)

st.markdown('<p style="font-size: 0.75rem; color: #777777; text-align: center; margin-top: 15px;">🛡️ Proyecto Escudo Mayor - Aplicación de carácter estrictamente académico e informativo para la protección digital. No orientada a fines comerciales comerciales.</p>', unsafe_allow_html=True)
