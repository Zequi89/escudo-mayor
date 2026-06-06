import streamlit as st
import requests
import re
import base64
from urllib.parse import urlparse
from blacklist import PALABRAS_PELIGRO, PALABRAS_ALERTA

# --- CONFIGURACIÓN ---
st.set_page_config(page_title="Escudo Mayor", page_icon="🛡️", layout="centered")

# --- CSS SIMPLIFICADO ---
st.markdown("""
    <style>
    /* Los colores generales ahora los maneja el config.toml */
    
    h1, h2, h3, .titulo-siglo21 { color: #008a45 !important; font-weight: bold; }
    
    .stTextArea textarea, .stFileUploader { 
        background-color: #eafaf1 !important; color: #111111 !important; 
        border: 2px solid #008a45 !important; border-radius: 8px;
    }
    div.stButton > button { 
        background-color: #008a45 !important; color: #ffffff !important; 
        font-weight: bold; border-radius: 8px !important; border: none !important;
    }
    .caja-resultado { padding: 20px; border-radius: 8px; color: #111111 !important; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-top: 20px; }
    .resultado-rojo { background-color: #ffcccc; border-left: 10px solid #cc0000; }
    .resultado-amarillo { background-color: #fff2cc; border-left: 10px solid #d4aa00; }
    .resultado-verde { background-color: #d5f5e3; border-left: 10px solid #008a45; }
    </style>
    """, unsafe_allow_html=True)

# --- CABECERA ---
st.markdown("<h1 class='titulo-siglo21' style='text-align: center;'>🛡️ Escudo Mayor</h1>", unsafe_allow_html=True)
st.markdown("<h3 style='text-align: center; color: #555;'>SEC - Fortalecimiento Digital para el Adulto Mayor</h3>", unsafe_allow_html=True)

# --- FUNCIONES ---
def expandir_url(url_corta):
    try:
        response = requests.head(url_corta, allow_redirects=True, timeout=5)
        return response.url
    except: return url_corta

def consultar_apis_url(url_analizada):
    try:
        GOOGLE_API_KEY = st.secrets["GOOGLE_API_KEY"]
        VT_API_KEY = st.secrets["VT_API_KEY"]
        
        riesgo_google = False
        riesgo_vt = False
        
        # Google Safe Browsing
        url_google = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        res_google = requests.post(url_google, json={
            "client": {"clientId": "escudo-mayor", "clientVersion": "1.0"},
            "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": url_analizada}]}
        }).json()
        if "matches" in res_google: riesgo_google = True
        
        # VirusTotal
        url_id = base64.urlsafe_b64encode(url_analizada.encode()).decode().strip("=")
        res_vt = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": VT_API_KEY}).json()
        if res_vt.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0:
            riesgo_vt = True
            
        return riesgo_google, riesgo_vt
    except:
        return False, False

def procesar_imagen_ocr(archivo):
    try:
        url = "https://api.ocr.space/parse/image"
        files = {'file': archivo}
        payload = {'apikey': st.secrets["OCR_API_KEY"], 'language': 'spa'}
        response = requests.post(url, files=files, data=payload)
        res_json = response.json()
        if res_json.get("ParsedResults"): 
            return res_json["ParsedResults"][0]["ParsedText"]
        return None
    except:
        return None

def ejecutar_analisis(texto):
    st.info("⏳ Analizando contenido y enlaces...")
    
    puntaje = 0
    encontradas = []
    for p in PALABRAS_PELIGRO: 
        if p in texto.lower(): puntaje += 2; encontradas.append(p)
    for p in PALABRAS_ALERTA: 
        if p in texto.lower(): puntaje += 1; encontradas.append(p)
    
    urls = re.findall(r'(https?://[^\s]+)', texto)
    url_info = ""
    riesgo_url = False
    
    if urls:
        url_original = urls[0].strip(".,!?\"'")
        url_final = expandir_url(url_original)
        riesgo_g, riesgo_v = consultar_apis_url(url_final)
        
        dominio = urlparse(url_final).netloc
        if url_original != url_final:
            url_info = f"⚠️ **Enlace acortado.** Redirecciona a: `{dominio}`"
            riesgo_url = True
        else:
            url_info = f"🌐 **Enlace detectado:** `{dominio}`"
            
        if riesgo_g or riesgo_v:
            url_info += " 🚫 **¡URL MARCADA COMO MALICIOSA!**"
            riesgo_url = True

    if puntaje >= 3 or riesgo_url:
        st.markdown(f"""
        <div class="caja-resultado resultado-rojo">
            <h2 style="color: #cc0000; margin-top: 0;">🔴 ¡ALERTA!</h2>
            <p>El texto contiene palabras sospechosas. <b>No acceda a enlaces ni brinde información personal.</b></p>
            <p>{url_info}</p>
            <p>🚩 <b>Palabras sospechosas:</b> {', '.join(set(encontradas)) if encontradas else 'Ninguna'}</p>
        </div>
        """, unsafe_allow_html=True)
    elif puntaje > 0:
        st.markdown(f"""
        <div class="caja-resultado resultado-amarillo">
            <h2 style="color: #b38600; margin-top: 0;">🟡 PRECAUCIÓN</h2>
            <p>El texto parece sospechoso. No hagas transferencias ni des claves.</p>
            <p>{url_info}</p>
            <p>🚩 <b>Palabras sospechosas:</b> {', '.join(set(encontradas))}</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="caja-resultado resultado-verde">
            <h2 style="color: #008a45; margin-top: 0;">🟢 PARECE SEGURO</h2>
            <p>No detectamos trampas en este mensaje.</p>
        </div>
        """, unsafe_allow_html=True)

# --- INTERFAZ ---
tab1, tab2 = st.tabs(["📸 Subir Captura", "✍️ Pegar Texto"])

with tab1:
    archivo = st.file_uploader("**Subí la captura:**", type=["png", "jpg", "jpeg"], key="uploader_img")
    if archivo is not None and st.button("👁️ Procesar Imagen"):
        with st.spinner("Leyendo imagen..."):
            texto_ext = procesar_imagen_ocr(archivo)
            if texto_ext:
                st.success("¡Texto detectado exitosamente!")
                st.text_area("Transcripción de la imagen:", value=texto_ext, height=150)
                ejecutar_analisis(texto_ext)
            else:
                st.error("No se pudo leer texto en la imagen.")

with tab2:
    texto = st.text_area("**Pegá el mensaje sospechoso aquí:**", height=150)
    if st.button("🔍 Analizar Texto"):
        if texto.strip(): ejecutar_analisis(texto)

st.write("---")
st.info("💡 **RECORDÁ:** Ningún organismo, banco, empresa de servicios, obra social o prepaga te pedirá claves o tokens por mensaje. Ante cualquier duda, cortá la comunicación y contactate siempre a través de los canales oficiales.")
