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

# Inicialización de Estados de Navegación Remota
if "active_tab" not in st.session_state:
    st.session_state["active_tab"] = "imagen"

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
# 3. ESTILOS VISUALES DINÁMICOS E INYECCIÓN DE CSS (TABS 50/50)
# ==============================================================================
# Definición de colores adaptativos para las solapas según la selección actual
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
    h1, h2, h3, .titulo-siglo21 {{ color: #008a45 !important; font-weight: bold; text-align: center; }}
    
    /* Configuración de Inyección de Solapas */
    {css_tabs}
    
    /* Cajas de texto y uploader estilizadas */
    .stTextArea textarea, .stFileUploader {{ 
        background-color: #eafaf1 !important; color: #111111 !important; 
        border: 2px solid #008a45 !important; border-radius: 8px !important;
    }}
    
    /* Estilos globales para botones operativos estándar */
    div.stButton > button:not([key^="tab_"]) {{ 
        background-color: #008a45 !important; color: #ffffff !important; 
        font-weight: bold; border-radius: 8px !important; border: none !important;
        padding: 0.5rem 1rem;
    }}
    
    /* Contenedores de Semáforos */
    .caja-resultado {{ padding: 20px; border-radius: 8px; color: #111111 !important; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-top: 15px; margin-bottom: 15px; }}
    .resultado-rojo {{ background-color: #ffcccc; border-left: 10px solid #cc0000; }}
    .resultado-amarillo {{ background-color: #fff2cc; border-left: 10px solid #d4aa00; }}
    .resultado-verde {{ background-color: #d5f5e3; border-left: 10px solid #008a45; }}
    
    .metrica-forense {{ font-family: monospace !important; font-size: 0.85rem; background-color: #0f172a; padding: 18px; border-radius: 6px; color: #38bdf8 !important; overflow-x: auto; line-height: 1.4; }}
    </style>
    """, unsafe_allow_html=True)

st.markdown("<h1 class='titulo-siglo21'>🛡️ Escudo Mayor</h1>", unsafe_allow_html=True)
st.markdown("<h3 style='color: #555; font-size: 1.1rem;'>Fortalecimiento Digital para el Adulto Mayor</h3>", unsafe_allow_html=True)

# ==============================================================================
# 4. MÓDULOS DE INFRAESTRUCTURA FORENSE AVANZADA
# ==============================================================================
def limpiar_errores_ocr(t):
    """Corrige desviaciones y artefactos de lectura óptica comunes"""
    t = re.sub(r'(\b[a-zA-Z0-9-]+)\s*\.\s*([a-zA-Z0-9.-]+)', r'\1.\2', t) # Quitar espacios inter-puntos
    t = re.sub(r'\bw\s*\.\s*w\s*\.\s*w\b', 'www', t, flags=re.IGNORECASE)   # w . w . w -> www
    t = re.sub(r'\bww\s*\.\s*w\b', 'www', t, flags=re.IGNORECASE)           # ww . w -> www
    t = re.sub(r'\bw\s*\.\s*ww\b', 'www', t, flags=re.IGNORECASE)           # w . ww -> www
    return t

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
        # Remover subdominios para consulta WHOIS estable si aplica
        dom_base = dominio
        partes = dominio.split('.')
        if len(partes) > 2 and partes[0] in ['www', 'w', 'ww']:
            dom_base = ".".join(partes[1:])
            
        w = whois.whois(dom_base)
        return {
            "registrador": w.get("registrar"),
            "fecha_creacion": w.get("creation_date"),
            "fecha_expiracion": w.get("expiration_date"),
            "pais_registro": w.get("country"),
            "organizacion": w.get("org")
        }
    except: return None

def auditar_ssl(dominio):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=dominio) as s:
            s.settimeout(5)
            s.connect((dominio, 443))
            cert = s.getpeercert()
            return True, cert
    except Exception as e: return False, str(e)

@st.cache_data(ttl=3600)
def consultar_apis_reputacion_completa(url_analizada):
    res_final = {
        "google_match": False, "google_detalles": "Sin alertas",
        "vt_maliciosos": 0, "vt_stats": {}
    }
    try:
        GOOGLE_API_KEY = st.secrets["GOOGLE_API_KEY"]
        url_google = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        payload = {
            "client": {"clientId": "escudo-mayor", "clientVersion": "2.0"},
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
            res_final["google_detalles"] = f"Alerta de {res_g['matches'][0]['threatType']} detectada en {res_g['matches'][0]['platformType']}"
    except: pass

    try:
        VT_API_KEY = st.secrets["VT_API_KEY"]
        url_id = base64.urlsafe_b64encode(url_analizada.encode()).decode().strip("=")
        res_v = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": VT_API_KEY}, timeout=5).json()
        stats = res_v.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        res_final["vt_maliciosos"] = stats.get('malicious', 0)
        res_final["vt_stats"] = stats
    except: pass
    
    return res_final

@st.cache_data(ttl=3600)
def buscar_osint_fraude_detallado(dominio):
    try:
        api_key = st.secrets.get("GOOGLE_SEARCH_API_KEY")
        cx = st.secrets.get("GOOGLE_CX")
        if not api_key or not cx: return 0, []
        url = f"https://www.googleapis.com/customsearch/v1?q=estafa+fraude+phishing+{dominio}&key={api_key}&cx={cx}"
        res = requests.get(url, timeout=5).json()
        total = int(res.get("searchInformation", {}).get("totalResults", "0"))
        items = res.get("items", [])
        snippets = [i.get("snippet") for i in items[:2]]
        return total, snippets
    except: return 0, []

# ==============================================================================
# 5. MOTOR DE CORRELACIÓN DE INTELIGENCIA UNIFICADO
# ==============================================================================
def ejecutar_analisis(texto_crudo):
    st.info("⏳ Desplegando telemetría avanzada y analizando vectores...")
    
    # Sanitización de la capa OCR/Texto
    texto_limpio = limpiar_errores_ocr(texto_crudo)
    texto_original = texto_limpio
    texto_traducido = None
    texto_analizar = texto_limpio
    
    # Módulo de traducción bidireccional integrado
    try:
        from deep_translator import GoogleTranslator
        texto_traducido = GoogleTranslator(source='auto', target='es').translate(texto_limpio)
        if texto_traducido and texto_traducido.strip().lower() != texto_limpio.strip().lower():
            texto_analizar = texto_traducido
    except:
        pass

    # Extracción inclusiva basada en especificaciones IANA TLD
    urls_completas = re.findall(r'(https?://[^\s]+)', texto_analizar)
    dominios_sueltos = re.findall(r'\b(?:[a-zA-Z0-9](?:[-a-zA-Z0-9]*[a-zA-Z0-9])?\.)+(?:[a-zA-Z]{2,6})\b', texto_analizar)
    emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', texto_analizar)
    telefonos = re.findall(r'(?:\+54\s?9\s?)?(?:11|[23]\d{2})\s?\d{4}[\-\s]?\d{4}', texto_analizar) 
    
    riesgo_critico = False
    motivo_riesgo = []
    
    # Encabezado del Log Forense Completo
    log_forense = [
        "======================================================================",
        "          INFORME DE AUDITORÍA FORENSE AVANZADA - ESCUDO MAYOR        ",
        "======================================================================",
        f"Fecha del Análisis: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "----------------------------------------------------------------------"
    ]
    map_data = None
    
    # Análisis de Textos y Patrones
    if emails:
        log_forense.append(f"[+] Correos Electrónicos Identificados: {', '.join(emails)}")
        motivo_riesgo.append(f"📧 **Remitente o dirección sospechosa:** {', '.join(emails)}")
    if telefonos:
        log_forense.append(f"[+] Líneas de Contacto Telefónico: {', '.join(telefonos)}")
        motivo_riesgo.append(f"📱 **Número de contacto detectado:** {', '.join(telefonos)}")

    palabras_encontradas = [p for p in PALABRAS_PELIGRO + PALABRAS_ALERTA if p in texto_analizar.lower()]
    if palabras_encontradas:
        palabras_str = ", ".join(set(palabras_encontradas))
        motivo_riesgo.append(f"🛑 **Lógica de manipulación emocional detectada:** Contiene palabras clave como: *{palabras_str}*.")
        log_forense.append(f"[!] Coincidencia de Palabras en Lista Negra: {palabras_str}")
        if any(p in texto_analizar.lower() for p in PALABRAS_PELIGRO):
            riesgo_critico = True
    
    # Consolidación única de dominios fidedignos
    dominios_a_analizar = set()
    for u in urls_completas:
        url_f = expandir_url(u.strip(".,!?\"'"))
        dominios_a_analizar.add(urlparse(url_f).netloc)
        
    for dom in dominios_sueltos:
        if dom.lower() not in ['png', 'jpg', 'jpeg', 'pdf', 'txt', 'html']:
            dominios_a_analizar.add(dom.lower())
            
    for email in emails:
        dominios_a_analizar.add(email.split('@')[-1])

    # Pipeline Forense Profundo por cada Dominio
    if dominios_a_analizar:
        for dom in dominios_a_analizar:
            log_forense.append(f"\n🔬 ANALIZANDO ENTIDAD OBJETIVO: {dom}")
            log_forense.append("-" * 54)
            
            # 1. Análisis de Typosquatting
            for marca in MARCAS_OFICIALES:
                if 0.75 < SequenceMatcher(None, dom, marca).ratio() < 1.0:
                    riesgo_critico = True
                    log_forense.append(f"[CRÍTICO] Patrón Typosquatting detectado para semejanza con: {marca}")
                    motivo_riesgo.append(f"🎭 **Intento de Suplantación:** La dirección `{dom}` intenta hacerse pasar por el sitio oficial `{marca}`.")
                    break

            # 2. Infraestructura DNS y Geolocalización Completa
            dns_info, geo_info = analizar_infraestructura_completa(dom)
            log_forense.append(f"[*] DNS - Dirección IP: {dns_info['ip']}")
            if dns_info['alias']:
                log_forense.append(f"[*] DNS - Reverso de Servidor: {dns_info['alias']}")
            
            if geo_info:
                log_forense.append(f"[*] GEO - Proveedor de Hosting / Org: {geo_info.get('org')}")
                log_forense.append(f"[*] GEO - Ubicación Física: {geo_info.get('city')}, {geo_info.get('region')}, {geo_info.get('country_name')}")
                map_data = pd.DataFrame({'lat': [geo_info.get('latitude')], 'lon': [geo_info.get('longitude')]})

            # 3. Auditoría WHOIS Rigurosa
            w_datos = auditar_whois_profundo(dom)
        if w_datos and isinstance(w_datos, dict):
            registrar = w_datos.get('registrar', 'No disponible')
            fc = w_datos.get('fecha_creacion')
            fe = w_datos.get('fecha_expiracion', 'No disponible')
            pais = w_datos.get('pais_registro', 'No disponible')

            log_forense.append(f"[*] WHOIS - Registrador: {registrar}")
            log_forense.append(f"[*] WHOIS - Fecha de Creación: {fc if fc else 'No disponible'}")
            log_forense.append(f"[*] WHOIS - Fecha de Vencimiento: {fe}")
            log_forense.append(f"[*] WHOIS - País Registrante: {pais}")
            
            if isinstance(fc, list) and len(fc) > 0: 
                fc = fc[0]
            
            if fc:
                try:
                    if hasattr(fc, 'tzinfo') and fc.tzinfo is not None:
                        fc = fc.replace(tzinfo=None)
                    
                    if isinstance(fc, datetime):
                        antiguedad = (datetime.now() - fc).days
                        log_forense.append(f"[*] WHOIS - Antigüedad Total del Dominio: {antiguedad} días")
                        if antiguedad < 30:
                            riesgo_critico = True
                            motivo_riesgo.append(f"⏱️ **Sitio Creado Recientemente:** El dominio tiene solo {antiguedad} días de vida (Comportamiento común de fraudes temporales).")
                    else:
                        log_forense.append(f"[-] WHOIS - Formato de fecha no compatible para cálculo analítico: {type(fc)}")
                except Exception as e:
                    log_forense.append(f"[-] WHOIS - Error estructural en el cálculo de antigüedad: {str(e)}")
        else:
            log_forense.append("[-] WHOIS - Registro Privado o Imposible de recuperar.")
            
            # 4. Auditoría de Seguridad SSL
            ssl_valido, ssl_detalles = auditar_ssl(dom)
            if ssl_valido:
                log_forense.append("[*] SSL - Estado: Certificado Cifrado Válido Emmitido.")
            else:
                log_forense.append(f"[-] SSL - Alerta: Falla estructural en cifrado HTTPS o Ausencia: {ssl_detalles}")

            # 5. Interrogación a APIs de Reputación
            rep = consultar_apis_reputacion_completa(dom)
            if rep["google_match"]:
                riesgo_critico = True
                log_forense.append(f"[ALERTA] Google Safe Browsing: {rep['google_detalles']}")
                motivo_riesgo.append("🚨 **Lista Negra de Google:** Marcado de forma oficial como sitio malicioso.")
            
            if rep["vt_maliciosos"] > 0:
                riesgo_critico = True
                log_forense.append(f"[ALERTA] VirusTotal Flag: {rep['vt_maliciosos']} motores detectaron anomalías.")
                log_forense.append(f"    -> Desglose de análisis: {rep['vt_stats']}")
                motivo_riesgo.append(f"🦠 **Alertas Técnicas:** {rep['vt_maliciosos']} firmas de antivirus catalogan la dirección como Phishing/Fraude.")

            # 6. Módulo OSINT Extendido
            total_osint, fragmentos = buscar_osint_fraude_detallado(dom)
            log_forense.append(f"[*] OSINT - Menciones públicas de fraude/estafa en Google: {total_osint}")
            if total_osint > 0:
                motivo_riesgo.append(f"🔍 **Denuncias Públicas Recurrentes:** Existen búsquedas indexadas vinculando a `{dom}` con estafas.")
                for f in fragmentos:
                    log_forense.append(f"    -> Reporte público: {f}")

    # ==============================================================================
    # 6. MÓDULO VISUAL: SEMÁFORO INTELIGENTE
    # ==============================================================================
    if motivo_riesgo:
        razones_html = "".join([f"<li>{m}</li>" for m in set(motivo_riesgo)])
    else:
        razones_html = "<li>No se han detectado patrones de manipulación evidentes ni anomalías en la infraestructura de red.</li>"

    if riesgo_critico or (urls_completas and palabras_encontradas):
        st.markdown(f"""
        <div class="caja-resultado resultado-rojo">
            <h2 style="color: #cc0000; margin-top:0;">🔴 ALERTA DE PELIGRO CRÍTICO</h2>
            <p><b>Se recomienda interrumpir de inmediato cualquier tipo de interacción. Los sistemas forenses confirman un vector de ataque activo.</b></p>
            <ul>{razones_html}</ul>
        </div>
        """, unsafe_allow_html=True)
    elif palabras_encontradas or telefonos or emails:
        st.markdown(f"""
        <div class="caja-resultado resultado-amarillo">
            <h2 style="color: #b48600; margin-top:0;">🟡 PRECAUCIÓN MÁXIMA RECOMENDADA</h2>
            <p><b>Mensaje con indicios sospechosos basados en patrones conductuales. Valide la identidad de la entidad por canales oficiales.</b></p>
            <ul>{razones_html}</ul>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="caja-resultado resultado-verde">
            <h2 style="color: #008a45; margin-top:0;">🟢 ANÁLISIS SIN ANOMALÍAS AUTOMÁTICAS</h2>
            <p>El sistema no detectó registros maliciosos inmediatos. De igual forma, recuerde que las instituciones legítimas nunca solicitarán credenciales privadas de forma inesperada.</p>
        </div>
        """, unsafe_allow_html=True)

    # Bloque de Despliegue de Resultados del Pipeline de Texto (Original vs Traducción)
    st.write("---")
    st.markdown("### 📝 Contenido Recuperado del Pipeline:")
    if texto_traducido and texto_traducido.strip().lower() != texto_original.strip().lower():
        st.text_area("Texto Original Capturado:", value=texto_original, height=100, key=f"orig_{random.randint(1,9999)}")
        st.text_area("Traducción Automática al Español (Utilizada para Correlación de Contenido):", value=texto_traducido, height=100, key=f"trad_{random.randint(1,9999)}")
    else:
        st.text_area("Texto Bajo Análisis:", value=texto_original, height=120, key=f"edit_{random.randint(1,9999)}")

    # Reporte Forense Técnico Exhaustivo en Desplegable Monocromático de Terminal
    with st.expander("🛠️ Ver Reporte Forense Completo de Infraestructura (Consola Técnica)", expanded=False):
        st.markdown(f"<div class='metrica-forense'>{'<br>'.join(log_forense).replace('\n', '<br>')}</div>", unsafe_allow_html=True)
        if map_data is not None and not map_data.isnull().values.any():
            st.write("**Coordenadas de Alojamiento del Servidor Encontrado:**")
            st.map(map_data, zoom=2)

# ==============================================================================
# 7. INTERFAZ DE USUARIO CONSOLIDADA (CUSTOM BALANCED TABS 50/50)
# ==============================================================================
col_tab1, col_tab2 = st.columns(2)

with col_tab1:
    if st.button("📸 Analizar Imagen / Captura", use_container_width=True, key="tab_imagen_btn"):
        st.session_state["active_tab"] = "imagen"
        st.rerun()

with col_tab2:
    if st.button("✍️ Analizar Texto Manual", use_container_width=True, key="tab_texto_btn"):
        st.session_state["active_tab"] = "texto"
        st.rerun()

st.write("") # Espaciador simétrico de control visual

# Ejecución Condicional Aislada por Solapa
if st.session_state["active_tab"] == "imagen":
    st.markdown("**Suba la captura de pantalla o imagen de su dispositivo móvil:**")
    archivo = st.file_uploader("", type=["png", "jpg", "jpeg"], key="uploader_automatizado")
    
    if archivo is not None:
        # Generar un identificador único del archivo cargado para evitar bucles infinitos de procesamiento
        file_id = f"{archivo.name}_{archivo.size}"
        if st.session_state.get("last_processed_file_id") != file_id:
            with st.spinner("Ejecutando descifrado óptico (OCR) y análisis automático instantáneo..."):
                texto_ocr = procesar_imagen_ocr(archivo)
                st.session_state["stored_text_ocr"] = texto_ocr
                st.session_state["last_processed_file_id"] = file_id
        
        # Despliegue automático de resultados si existe texto válido
        if st.session_state.get("stored_text_ocr"):
            ejecutar_analisis(st.session_state["stored_text_ocr"])
        elif st.session_state.get("stored_text_ocr") == "":
            st.error("No se pudo detectar texto legible dentro de la captura cargada.")
else:
    st.markdown("**Introduzca cualquier fragmento de mensaje, correo electrónico o dirección web sospechosa:**")
    texto_ingresado = st.text_area("", height=150, placeholder="Ejemplo de dominio plano: bna.com.ar o ingrese el cuerpo del mensaje de texto...", key="input_consola_manual")
    if st.button("🔍 Iniciar Análisis de Texto", use_container_width=True):
        if texto_ingresado.strip(): 
            ejecutar_analisis(texto_ingresado)
        else:
            st.warning("Ingrese un texto o enlace.")

# ==============================================================================
# 8. MÓDULO INTERACTIVO DE TRIVIA DIARIA (CONTENEDOR SEGURO)
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
            st.error(f"**Atención:** La respuesta sugerida era **{q['respuesta']}**. {q['explicacion']}")

# ==============================================================================
# 9. REFUERZO DE SEGURIDAD OPERATIVA Y MARCO LEGAL
# ==============================================================================
st.write("---")
with st.container(border=True):
    st.markdown("""
    💡 <b>RECORDATORIO:</b> Ningún organismo, banco, empresa de servicios, obra social o prepaga te pedirá claves o tokens por mensaje. Ante cualquier duda, contactate través de los canales oficiales.
    """, unsafe_allow_html=True)

st.markdown('<p style="font-size: 0.75rem; color: #777777; text-align: center; margin-top: 15px;">🛡️ Proyecto Escudo Mayor - Aplicación de carácter académico para la protección digital. No orientada a fines comerciales.</p>', unsafe_allow_html=True)
