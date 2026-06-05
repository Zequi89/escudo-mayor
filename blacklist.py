# blacklist.py
# Motor de Heurística Avanzado - Escudo Mayor

# =====================================================================
# NIVEL 2: PALABRAS DE ALTA PELIGROSIDAD (Puntaje: 2 por palabra)
# Indica compromiso inminente, infección o intento de toma de control.
# =====================================================================
PALABRAS_PELIGRO = [
    # Credenciales y accesos críticos
    "cbu", "cvu", "token", "contraseña", "clave", "pin", "código de 6 dígitos",
    "código de verificación", "sms", "home banking", "coordenadas", "foto del dni",
    "clave de cajero", "usuario y password", "biometría", "clave bancaria",
    
    # Infecciones y Malware técnico
    "virus", "troyano", "gusano", "infección", "malware", "ransomware", 
    "spyware", "archivo ejecutable", "script", "hackeo", "hackeado",
    "sistema comprometido", "vulnerabilidad", "actualización de seguridad",
    
    # Robo y Secuestro de Identidad/Datos
    "robo", "secuestro", "secuestrado", "extorsión", "exfiltración", 
    "datos personales", "archivos cifrados", "pago de rescate", 
    "suplantación", "phishing", "smishing", "vishing",
    
    # Acciones financieras de alto riesgo
    "transferencia", "transferir", "débito automático", "link de pago", 
    "adelanto", "préstamo preaprobado", "pago rechazado", "deuda pendiente", 
    "embargo preventivo", "alias", "pago urgente", "transferir fondos",
    
    # Urgencia por bloqueo o penalidad (Generación de pánico)
    "desactivado", "bloqueado", "suspendida", "verificación requerida", 
    "cuenta inhabilitada", "robo de identidad", "validar identidad", 
    "actualizar datos", "código de seguridad", "vincular dispositivo", 
    "actividad inusual", "intento de inicio de sesión", "acceso no autorizado",
    "evitar multa", "evitar clausura", "último aviso", "suspenderemos su cuenta",
    
    # Herramientas de acceso remoto (Estafa de soporte técnico)
    "teamviewer", "anydesk", "descargar aplicación", "instalar apk", 
    "soporte remoto", "control de pantalla", "acceso administrativo"
]

# =====================================================================
# NIVEL 1: GANCHOS E INGENIERÍA SOCIAL (Puntaje: 1 por palabra)
# Contexto de engaño y suplantación de identidad.
# =====================================================================
PALABRAS_ALERTA = [
    # Suplantación de identidad familiar / Cuento del tío
    "agendame", "cambié mi número", "este es mi nuevo número", 
    "tuve un accidente", "necesito un favor", "me prestás", "estoy en el hospital",
    "urgencia familiar", "hola ma", "hola pa", "tío", "tía", "dólares", "cara chica",
    "necesito dinero", "ayuda", "operación urgente", "estoy varado",
    
    # Instituciones y Servicios Públicos
    "anses", "afip", "pami", "mi argentina", "ministerio de salud", 
    "policia", "bcra", "banco central", "rentas", "arba", "ioma",
    "tarjeta alimentar", "repro", "receta digital", "credencial digital",
    "cuit", "cuil", "expediente", "judicial", "orden de arresto",
    
    # Entidades Financieras
    "mercado pago", "mercadopago", "uala", "naranja x", "cuenta dni", 
    "modo", "personal pay", "prex", "lemon", "belo",
    "banco nacion", "bna", "banco provincia", "santander", "galicia", 
    "bbva", "macro", "icbc", "brubank", "bancor", "credicoop", "hsbc",
    
    # Logística y Paquetería
    "correo argentino", "andreani", "oca", "dhl", "fedex", 
    "paquete retenido", "aduana", "entrega fallida", "costos de envío", 
    "reprogramar entrega", "dirección incorrecta", "envío pendiente",
    
    # Servicios básicos y prepagas
    "edesur", "edenor", "aysa", "metrogas", "personal", "claro", "movistar", 
    "telecentro", "osde", "swiss medical", "galeno", "corte de luz", 
    "corte de servicio", "factura vencida", "deuda de servicio",
    
    # Ganchos de marketing engañoso
    "premio", "ganaste", "urgente", "sorteo", "regalo", "bono", 
    "ife", "subsidio", "jubilacion", "vencimiento", "promocion", 
    "soporte", "atención al cliente", "felicidades", "ganador", "cupo limitado",
    "sorteo especial", "beneficio exclusivo", "reembolso", "devolución de impuestos"
]