# ==============================================================================
# BASE DE DATOS DE TRIVIA - ESCUDO MAYOR
# ==============================================================================

TRIVIA_SEGURIDAD = [
    # --- PREGUNTAS ORIGINALES DEL USUARIO (1-20) ---
    {
        "pregunta": "Recibe un mensaje de ANSES diciendo que su bono está bloqueado y debe hacer clic en un enlace. ¿Qué debe hacer?",
        "opciones": ["Hacer clic rápido para no perder el bono.", "Ignorar y borrar el mensaje.", "Reenviarlo a todos sus contactos."],
        "respuesta": "Ignorar y borrar el mensaje.",
        "explicacion": "ANSES nunca pide datos ni avisa de bloqueos mediante enlaces por SMS o WhatsApp."
    },
    {
        "pregunta": "¿Un representante del banco le puede pedir el código (Token) que le llegó por SMS para 'cancelar un fraude'?",
        "opciones": ["Sí", "No"],
        "respuesta": "No",
        "explicacion": "El banco jamás le pedirá su Token. Los estafadores lo usan para vaciar su cuenta."
    },
    {
        "pregunta": "Un familiar le escribe por WhatsApp desde un número nuevo diciendo que chocó y necesita una transferencia urgente. ¿Qué hace?",
        "opciones": ["Le transfiero el dinero inmediatamente.", "Lo llamo a su número de siempre para comprobar si es verdad."],
        "respuesta": "Lo llamo a su número de siempre para comprobar si es verdad.",
        "explicacion": "Es una estafa común. Siempre debe verificar llamando al número original de su familiar."
    },
    {
        "pregunta": "¿Es seguro usar la red WiFi gratuita de un café para revisar su cuenta bancaria?",
        "opciones": ["Sí, es seguro.", "No, no es seguro."],
        "respuesta": "No, no es seguro.",
        "explicacion": "Las redes públicas pueden ser interceptadas. Use sus datos móviles para transacciones bancarias."
    },
    {
        "pregunta": "Le avisan que ganó un sorteo de un auto, pero debe pagar los 'gastos administrativos' para recibirlo. ¿Qué significa?",
        "opciones": ["Que gané un auto.", "Que es una estafa."],
        "respuesta": "Que es una estafa.",
        "explicacion": "Los premios reales no requieren que usted pague dinero por adelantado."
    },
    {
        "pregunta": "¿Para qué sirve el 'candado' que aparece en la barra de direcciones de internet (arriba en el navegador)?",
        "opciones": ["Indica que la conexión es privada y segura.", "Significa que la página nunca tendrá virus."],
        "respuesta": "Indica que la conexión es privada y segura.",
        "explicacion": "El candado (HTTPS) cifra la información, pero ojo: páginas falsas también pueden tenerlo. Siempre revise el nombre de la página."
    },
    {
        "pregunta": "Si le roban el celular, ¿qué es lo primero que debe hacer además de avisar a su familia?",
        "opciones": ["Comprar otro celular.", "Llamar a su operadora para bloquear la línea y al banco para bloquear sus cuentas."],
        "respuesta": "Llamar a su operadora para bloquear la línea y al banco para bloquear sus cuentas.",
        "explicacion": "Bloquear la línea y las aplicaciones financieras evita que los ladrones roben su dinero."
    },
    {
        "pregunta": "Netflix le envía un correo diciendo que su cuenta será suspendida si no actualiza su tarjeta hoy. ¿Cómo procede?",
        "opciones": ["Entro a la página oficial de Netflix escribiéndola yo mismo en el navegador.", "Hago clic en el botón del correo y pongo mi tarjeta."],
        "respuesta": "Entro a la página oficial de Netflix escribiéndola yo mismo en el navegador.",
        "explicacion": "Los correos falsos (Phishing) buscan robar los datos de su tarjeta asustándolo con suspensiones."
    },
    {
        "pregunta": "¿Qué es el 'Phishing'?",
        "opciones": ["Un deporte acuático.", "Una técnica donde el estafador se hace pasar por una empresa de confianza para robar datos."],
        "respuesta": "Una técnica donde el estafador se hace pasar por una empresa de confianza para robar datos.",
        "explicacion": "Se llama así porque los estafadores lanzan 'anzuelos' esperando que alguien muerda y entregue sus datos."
    },
    {
        "pregunta": "¿Debería usar la misma contraseña para su correo, su banco y su Facebook?",
        "opciones": ["Sí, es más fácil de recordar.", "No, debe ser diferente."],
        "respuesta": "No, debe ser diferente.",
        "explicacion": "Si usa la misma contraseña y un estafador la descubre, tendrá acceso a toda su vida digital."
    },
    {
        "pregunta": "Le llega un comprobante de transferencia por WhatsApp de un comprador, pero el dinero no aparece en su cuenta. ¿Qué hace?",
        "opciones": ["Le entrego el producto porque el comprobante parece real.", "No entrego nada hasta ver el dinero en los movimientos de mi cuenta."],
        "respuesta": "No entrego nada hasta ver el dinero en los movimientos de mi cuenta.",
        "explicacion": "Los comprobantes falsos son muy fáciles de hacer. La única verdad está en su propia aplicación del banco."
    },
    {
        "pregunta": "Un empleado del ministerio de salud lo llama para darle turno para una vacuna y le pide que le dicte un código de 6 números. ¿Qué es ese código?",
        "opciones": ["El número de turno de la vacuna.", "El código para robarle su WhatsApp."],
        "respuesta": "El código para robarle su WhatsApp.",
        "explicacion": "Nadie necesita que le dicte un código por teléfono. Ese código de 6 dígitos es la llave de su WhatsApp."
    },
    {
        "pregunta": "¿Qué debe hacer si pierde su tarjeta de débito?",
        "opciones": ["Esperar unos días a ver si aparece.", "Reportarla inmediatamente en la aplicación del banco o por teléfono."],
        "respuesta": "Reportarla inmediatamente en la aplicación del banco o por teléfono.",
        "explicacion": "Reportarla la desactiva al instante, impidiendo que cualquiera que la encuentre pueda gastar su dinero."
    },
    {
        "pregunta": "Recibe un email de MercadoPago pidiendo 'Verificar su identidad' con un enlace extraño. ¿Es seguro?",
        "opciones": ["No", "Sí"],
        "respuesta": "No",
        "explicacion": "MercadoPago notifica dentro de su propia aplicación oficial. Los enlaces externos suelen ser estafas."
    },
    {
        "pregunta": "Si un perfil de Facebook o Instagram le ofrece duplicar su dinero en 24 horas invirtiendo en criptomonedas, ¿es real?",
        "opciones": ["No, es una estafa.", "Sí, si tiene muchos seguidores."],
        "respuesta": "No, es una estafa.",
        "explicacion": "No existe la plata fácil. Si le prometen ganancias mágicas y rápidas, le van a robar su inversión."
    },
    {
        "pregunta": "¿Es recomendable guardar las contraseñas escritas en un papel pegado a la computadora?",
        "opciones": ["Sí, así no las olvido.", "No, cualquiera que entre podría verlas."],
        "respuesta": "No, cualquiera que entre podría verlas.",
        "explicacion": "Guarde sus contraseñas en un cuaderno privado y lejos de la vista de terceros."
    },
    {
        "pregunta": "Una publicidad en internet le ofrece un celular de última generación a un 10% de su precio original. ¿Qué piensa?",
        "opciones": ["Es una oferta increíble, compro ya.", "Es demasiado bueno para ser verdad, seguro es una página fraudulenta."],
        "respuesta": "Es demasiado bueno para ser verdad, seguro es una página fraudulenta.",
        "explicacion": "Los precios irrealmente bajos son el cebo principal para que usted ingrese los datos de su tarjeta."
    },
    {
        "pregunta": "¿Qué información NUNCA debe compartir si alguien se lo pide por mensaje o llamada?",
        "opciones": ["Su nombre y apellido.", "Claves, tokens, CBU y números de tarjeta completos."],
        "respuesta": "Claves, tokens, CBU y números de tarjeta completos.",
        "explicacion": "Sus claves financieras son personales e intransferibles."
    },
    {
        "pregunta": "¿Qué significa que una página web empiece con 'https://'?",
        "opciones": ["Que la información viaja encriptada.", "Que es una página del gobierno."],
        "respuesta": "Que la información viaja encriptada.",
        "explicacion": "La 's' significa 'Seguro', la información viaja oculta, pero no garantiza que los dueños de la página sean honestos."
    },
    {
        "pregunta": "Alguien lo llama diciendo que tienen secuestrado a un familiar y le piden que pague un rescate rápido. ¿Qué es lo primero que debe hacer?",
        "opciones": ["Cortar la llamada e intentar contactar a su familiar inmediatamente.", "Juntar el dinero lo más rápido posible."],
        "respuesta": "Cortar la llamada e intentar contactar a su familiar inmediatamente.",
        "explicacion": "El 'secuestro virtual' juega con la desesperación. En el 99% de los casos, su familiar está bien. Corte y llámelo."
    },

    # --- CATEGORÍA: SEGURIDAD PARA ADULTOS MAYORES (21-70) ---
    {
        "pregunta": "Le llega un WhatsApp con el logo de PAMI informando que hay un nuevo carnet digital obligatorio y un link de descarga. ¿Qué hace?",
        "opciones": ["Hago clic para descargar el nuevo carnet.", "No abro el link y consulto en la agencia oficial o app oficial de PAMI."],
        "respuesta": "No abro el link y consulto en la agencia oficial o app oficial de PAMI.",
        "explicacion": "Los ciberdelincuentes usan el logo de PAMI en aplicaciones falsas para tomar el control de su teléfono."
    },
    {
        "pregunta": "La aplicación 'Mi Argentina' le pide validar su identidad con reconocimiento facial pero falla repetidamente. Un gestor en Facebook se ofrece a hacérselo por mensaje privado. ¿Qué decide?",
        "opciones": ["Le paso mis datos de acceso para que me ayude.", "Rechazo la ayuda. Ningún trámite oficial de Mi Argentina requiere dar claves a terceros."],
        "respuesta": "Rechazo la ayuda. Ningún trámite oficial de Mi Argentina requiere dar claves a terceros.",
        "explicacion": "Los falsos gestores en redes sociales roban identidades digitales para sacar créditos a su nombre."
    },
    {
        "pregunta": "Recibe un correo que parece del Banco Nación (BNA) advirtiendo sobre un 'ingreso sospechoso' a su home banking, con un botón que dice 'Desbloquear aquí'. ¿Qué observa primero?",
        "opciones": ["El color del botón.", "La dirección de correo del remitente para ver si termina en @bna.com.ar o es una dirección extraña."],
        "respuesta": "La dirección de correo del remitente para ver si termina en @bna.com.ar o es una dirección extraña.",
        "explicacion": "El Phishing clona el diseño del banco, pero la dirección del remitente suele ser un correo genérico o fraudulento."
    },
    {
        "pregunta": "En la aplicación 'Cuenta DNI', ¿es seguro pasarle una foto de su pantalla con el código QR de cobro/pago a un desconocido por redes?",
        "opciones": ["Sí, el QR es público.", "No, compartir códigos de transacciones o capturas dinámicas expone sus fondos."],
        "respuesta": "No, compartir códigos de transacciones o capturas dinámicas expone sus fondos.",
        "explicacion": "Las capturas de pantalla de la billetera digital con datos clave pueden ser manipuladas para realizar fraudes de triangulación."
    },
    {
        "pregunta": "Le suena el teléfono fijo y dicen ser de la compañía de gas, informando que si no realiza un pago virtual de inmediato por una 'boleta vencida', le cortarán el servicio en una hora. ¿Qué hace?",
        "opciones": ["Pago rápido para evitar el corte.", "Corto la comunicación y verifico el estado de mi deuda en la factura física o web oficial."],
        "respuesta": "Corto la comunicación y verifico el estado de mi deuda en la factura física o web oficial.",
        "explicacion": "El apuro y la amenaza de corte de servicios básicos son estrategias clásicas de la ingeniería social."
    },
    {
        "pregunta": "Un supuesto técnico de soporte técnico de Microsoft lo llama por teléfono diciendo que su computadora tiene virus y que debe instalar un programa de acceso remoto como AnyDesk para limpiarla. ¿Qué hace?",
        "opciones": ["Instalo el programa para que limpie mi PC.", "Corto la llamada. Microsoft nunca llama proactivamente a los usuarios."],
        "respuesta": "Corto la llamada. Microsoft nunca llama proactivamente a los usuarios.",
        "explicacion": "Si les da acceso remoto, los atacantes entrarán a sus carpetas personales y guardarán sus contraseñas bancarias."
    },
    {
        "pregunta": "Va al cajero automático y nota que la ranura donde se introduce la tarjeta de débito está floja o tiene un plástico superpuesto. ¿Qué debe hacer?",
        "opciones": ["Introducir la tarjeta igual empujando fuerte.", "No usar ese cajero y reportar la anomalía al banco o a la policía."],
        "respuesta": "No usar ese cajero y reportar la anomalía al banco o a la policía.",
        "explicacion": "Podría tratarse de un 'Skimmer', un dispositivo físico que clona la banda magnética de su tarjeta."
    },
    {
        "pregunta": "Al ingresar su contraseña en el cajero automático, ¿cuál es la mejor práctica de protección física?",
        "opciones": ["Digitarla rápido sin mirar.", "Tapar el teclado con una mano mientras digita los números con la otra."],
        "respuesta": "Tapar el teclado con una mano mientras digita los números con la otra.",
        "explicacion": "Esto evita que cámaras ocultas instaladas por delincuentes filmen su clave numérica (PIN)."
    },
    {
        "pregunta": "Si recibe un mensaje de texto SMS de un número corto desconocido que dice: 'Ganaste $500.000 de saldo. Envía ALTA al 9900', ¿cuál es el peligro?",
        "opciones": ["Es publicidad normal.", "Es una estafa de suscripción forzada que consumirá su crédito o le generará cargos."],
        "respuesta": "Es una estafa de suscripción forzada que consumirá su crédito o le generará cargos.",
        "explicacion": "Los SMS capciosos buscan suscribir la línea a servicios pagos premium sin el consentimiento real del usuario."
    },
    {
        "pregunta": "Su nieto le pide que le preste su celular para jugar. ¿Qué precaución de seguridad básica debería tener configurada en la tienda de aplicaciones?",
        "opciones": ["Ninguna, es su nieto.", "Requerir autenticación (huella o clave) para cada compra o descarga de apps."],
        "respuesta": "Requerir autenticación (huella o clave) para cada compra o descarga de apps.",
        "explicacion": "Evita gastos accidentales con tarjetas asociadas o la instalación involuntaria de software malicioso."
    },
    {
        "pregunta": "Un mensaje de WhatsApp de origen desconocido le promete un subsidio de la Tarjeta Alimentar completando una encuesta de 3 preguntas. ¿Qué ocurre si la completa?",
        "opciones": ["Recibo la tarjeta en mi domicilio.", "Le roban sus datos personales y lo usan para propagar malware a sus contactos."],
        "respuesta": "Le roban sus datos personales y lo usan para propagar malware a sus contactos.",
        "explicacion": "Las falsas encuestas institucionales colectan datos para bases de estafadores (phishing masivo)."
    },
    {
        "pregunta": "Si un amigo le envía por chat un enlace que dice '¡Mira este video tuyo!', pero la página le pide iniciar sesión en Facebook para verlo, ¿qué debe hacer?",
        "opciones": ["Poner mi usuario y contraseña rápido.", "No poner nada. A mi amigo le hackearon la cuenta y la página es falsa."],
        "respuesta": "No poner nada. A mi amigo le hackearon la cuenta y la página es falsa.",
        "explicacion": "Es un truco de robo de credenciales muy común distribuido automáticamente a través de cuentas comprometidas."
    },
    {
        "pregunta": "Aparece un cartel en su pantalla que dice: 'Su sistema Windows está dañado. Llame al 0800-XXX para repararlo'. ¿Qué estructura tiene este aviso?",
        "opciones": ["Es una alerta real del sistema operativo.", "Es un anuncio web fraudulento diseñado para asustarlo (Scareware)."],
        "respuesta": "Es un anuncio web fraudulento diseñado para asustarlo (Scareware).",
        "explicacion": "El sistema operativo jamás le pedirá llamar a un teléfono mediante ventanas emergentes del navegador de internet."
    },
    {
        "pregunta": "Le ofrecen por teléfono un préstamo a tasa cero exclusivo para jubilados, pero le piden que vaya al cajero a generar una 'clave de home banking provisoria' y se la dicte. ¿Qué hace?",
        "opciones": ["Voy al cajero y lo hago.", "Corto la llamada. Nunca se deben generar claves sugeridas por un tercero por teléfono."],
        "respuesta": "Corto la llamada. Nunca se deben generar claves sugeridas por un tercero por teléfono.",
        "explicacion": "Al dictar esa clave provisoria, el estafador toma control de su cuenta bancaria desde otro dispositivo."
    },
    {
        "pregunta": "¿Qué significa activar la 'Verificación en dos pasos' en WhatsApp?",
        "opciones": ["Que tengo que usar dos números de teléfono.", "Configurar un PIN de 6 dígitos que la app pedirá al instalarse en un nuevo celular."],
        "respuesta": "Configurar un PIN de 6 dígitos que la app pedirá al instalarse en un nuevo celular.",
        "explicacion": "Es la protección más eficaz para evitar que clonen o roben su cuenta de WhatsApp."
    },
    {
        "pregunta": "Le llega una notificación de que su cuenta de correo electrónico de Gmail cerrará por inactividad a menos que envíe su contraseña por responder el correo. ¿Cómo actúa?",
        "opciones": ["Respondo el mail con mis datos.", "Borro el correo. Google nunca solicita contraseñas por correo electrónico."],
        "respuesta": "Borro el correo. Google nunca solicita contraseñas por correo electrónico.",
        "explicacion": "Ningún proveedor legítimo de servicios digitales le pedirá su clave mediante un mensaje saliente."
    },
    {
        "pregunta": "Si compra un producto en un sitio web de comercio electrónico, ¿cuál es el método de pago más seguro para evitar que clonen su tarjeta principal?",
        "opciones": ["Tarjetas virtuales de un solo uso o billeteras digitales protegidas.", "Pasar los datos de mi tarjeta física por un mensaje de chat privado."],
        "respuesta": "Tarjetas virtuales de un solo uso o billeteras digitales protegidas.",
        "explicacion": "Las tarjetas virtuales expiran rápido y limitan el monto, blindando su cuenta principal ante filtraciones."
    },
    {
        "pregunta": "Un aviso en Facebook le promete turnos preferenciales para tramitar el pasaporte o DNI sin esperar en el Registro Civil a cambio de un depósito por Mercado Pago. ¿Qué debe hacer?",
        "opciones": ["Pagar para ahorrar tiempo.", "Ignorarlo. Los turnos oficiales se gestionan únicamente en los portales del Gobierno Nacional."],
        "respuesta": "Ignorarlo. Los turnos oficiales se gestionan únicamente en los portales del Gobierno Nacional.",
        "explicacion": "Es una modalidad de estafa que vende turnos falsos inexistentes usando marcas estatales."
    },
    {
        "pregunta": "Si un desconocido lo agrega a un grupo de WhatsApp de inversiones sin su permiso, ¿cuál es la mejor configuración de privacidad para su cuenta?",
        "opciones": ["Mantenerme en el grupo a ver qué pasa.", "Salir del grupo y configurar WhatsApp para que solo mis contactos puedan añadirme a grupos."],
        "respuesta": "Salir del grupo y configurar WhatsApp para que solo mis contactos puedan añadirme a grupos.",
        "explicacion": "Restringir quién puede agregarlo disminuye drásticamente la exposición a estafas cripto o esquemas Ponzi."
    },
    {
        "pregunta": "Recibe un mensaje de texto informando que el Correo Argentino tiene un paquete suyo retenido por falta de pago de tasas de aduana ($1500) y un link. Usted no compró nada afuera. ¿Qué hace?",
        "opciones": ["Hago clic por las dudas de que sea un regalo.", "Elimino el SMS. Es una campaña de phishing masiva para capturar datos de tarjetas."],
        "
