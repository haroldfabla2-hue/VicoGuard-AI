# 🎤 Guion del Pitch y Q&A del Jurado (3-5 Minutos)

## Guion Cronometrado de la Presentación

### Apertura (0:00 - 0:40) — Mariana
> "El 82% del código generado por IA tiene vulnerabilidades. Hoy, miles de emprendedores peruanos están lanzando apps con herramientas como Cursor, Lovable o Supabase sin saber que sus bases de datos están abiertas al mundo. En Perú, el 45% de las Pymes sufrió un incidente de ciberseguridad este año. 748 millones de ciberataques en solo 6 meses. Y la peor parte: una auditoría de seguridad tradicional cuesta miles de dólares. Las Pymes están ciegas y desprotegidas."

### La Demostración del Ataque (0:40 - 1:30) — Cristhian
> "Les voy a demostrar lo fácil que es. Esta es una tienda online real, creada con IA esta semana."  
> *(Abre terminal, ejecuta script de 3 líneas)*  
> "Ya está. Acabo de descargar la base de datos completa de clientes: nombres, correos, direcciones. Todo. Sin contraseña. Sin hackeo sofisticado. Solo una mala configuración que el 83% de los proyectos Supabase tienen."

### La Solución VicoGuard (1:30 - 2:30) — Alberto
> "Esto es exactamente lo que VicoGuard AI resuelve. Miren."  
> *(Ingresa la URL de la tienda en VicoGuard)*  
> "Nuestro agente autónomo de IA está analizando la aplicación ahora mismo. Escanea dependencias, busca secretos expuestos, y evalúa la configuración de la base de datos."  
> *(Pausa dramática. El teléfono suena en el escenario.)*  
> "Este es un mensaje de Telegram de VicoGuard. Dice: 'Tu base de clientes está expuesta. Cualquiera puede descargarla. Aquí tienes el código SQL exacto para protegerla.' Cero jerga. Cero PDF técnicos. Solo la solución, directo al celular."  
> *(Muestra el mensaje de Telegram en pantalla)*

### Monitoreo Continuo y Protocolo (2:30 - 3:15) — Daniel
> "Pero VicoGuard no solo escanea una vez. Después del despliegue, vigila tu servidor 24/7. Si detecta un ataque de fuerza bruta o una caída sospechosa, correlaciona los eventos con IA y te envía un solo mensaje claro, no 500 alertas incomprensibles."  
> *(Muestra ejemplo de alerta correlacionada en pantalla)*

### Modelo de Negocio y Cierre (3:15 - 4:00) — Mariana & Luis
> **Luis:** "Construimos esto en 12 horas con Python, Django y la API de Telegram. La arquitectura está diseñada para escalar a WhatsApp, correo electrónico y cualquier canal."  
> **Mariana:** "Nuestro modelo: Freemium para atraer Pymes, $29-49/mes para monitoreo continuo, y licencias de marca blanca para agencias digitales que gestionan cientos de clientes. El mercado de ciberseguridad en Perú vale 151 millones de euros y las Pymes están completamente desatendidas. VicoGuard AI democratiza la ciberseguridad. Gracias."

---

## Preguntas Difíciles del Jurado (Q&A Preparado)

| Pregunta del Jurado | Respuesta Preparada |
|---------------------|-------------------|
| "¿En qué se diferencia de Snyk o Dependabot?" | "Snyk y Dependabot son herramientas para desarrolladores senior. Generan reportes técnicos que un dueño de Pyme no puede leer. VicoGuard traduce todo a lenguaje natural y entrega la solución directamente por Telegram/WhatsApp. Además, monitoreamos el servidor post-despliegue, cosa que ellos no hacen." |
| "¿Cómo evitan los falsos positivos?" | "Usamos un motor de correlación con IA. En lugar de alertar por cada evento individual, acumulamos los eventos de un período y el LLM filtra el ruido de los bots inofensivos antes de alertar. Solo notificamos amenazas reales verificadas." |
| "¿Cuál es su go-to-market?" | "Product-Led Growth. Cualquier Pyme puede hacer un escaneo gratuito y recibir la alerta por Telegram. Ven el valor inmediatamente. Luego convertimos al plan Pro para monitoreo continuo. También vendemos licencias a agencias digitales que ya atienden a cientos de Pymes." |
| "¿Qué pasa si el usuario no entiende el parche SQL?" | "El asistente conversacional de Telegram permite al usuario preguntar 'Explícame esto como si tuviera 5 años' y la IA reformula la explicación. Además, estamos trabajando en botones de un clic para aplicar los parches más comunes automáticamente." |
| "¿Es seguro darle acceso a su servidor a una herramienta de IA?" | "VicoGuard NO necesita acceso al servidor para el escaneo inicial (es 100% externo/pasivo). Para el monitoreo, el agente solo lee logs, nunca tiene permisos de escritura ni acceso a datos sensibles de negocio." |
| "¿Cómo monetizan si el Freemium da tanto valor?" | "El Freemium es un escaneo puntual. El verdadero valor es el monitoreo 24/7 y las alertas en tiempo real del plan Pro. Es la diferencia entre hacerte un chequeo médico una vez al año y tener un doctor monitoreando tus signos vitales todos los días." |
