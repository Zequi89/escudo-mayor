# ==============================================================================
# BASE DE DATOS DE TRIVIA - ESCUDO MAYOR
# ==============================================================================

TRIVIA_SEGURIDAD = [
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
    }
]