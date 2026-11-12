# Para líderes de salud: una página

**El problema.** Los proveedores de inteligencia artificial están llegando a cada consultorio, clínica y hospital. Todos dicen que su producto es seguro para los datos de los pacientes. La mayoría de las organizaciones pequeñas no tiene cómo comprobarlo, y la mayoría de los proveedores pequeños no puede pagar los meses de consultoría que cuesta demostrarlo. Las herramientas útiles se quedan detenidas y las riesgosas entran con un apretón de manos.

**Qué es patient-zero.** Una lista abierta y gratuita de 43 salvaguardas que un producto de IA debe tener antes de tocar información de pacientes, escrita dos veces: una para los ingenieros que construyen el producto y otra en lenguaje sencillo para quienes lo compran. Incluye software que prueba algunas de esas salvaguardas de forma automática y empaqueta la evidencia de modo que no pueda modificarse después sin que se note.

**Lo que usted puede hacer hoy, sin personal técnico.**

1. **Envíe el cuestionario al proveedor.** [`VENDOR-QUESTIONNAIRE.md`](VENDOR-QUESTIONNAIRE.md) (en inglés) presenta cada salvaguarda como una pregunta sencilla e indica qué debe acompañar a una buena respuesta. Un proveedor que dice que sí pero no puede mostrar la evidencia no ha respondido.
2. **Pida un informe sellado.** Un proveedor que usa patient-zero puede entregarle un resumen de una página en lenguaje sencillo y un paquete de evidencia firmado. Si se cambia cualquier archivo después de la firma, la verificación falla.
3. **Revise los puntos de Nevada.** [`NEVADA.md`](NEVADA.md) (en inglés) cubre lo que la ley de Nevada añade para la IA: los límites de 2025 al uso de IA en la atención de salud mental y conductual (AB 406) y la ley de datos de salud del consumidor (SB 370).

**Cuánto cuesta.** Nada. Es código abierto con licencia MIT. Sin cuenta, sin cuota, y no envía datos a ningún lado.

**Lo que no es.**

- No es una certificación de HIPAA. Esa certificación no existe; el gobierno federal no la emite ni la reconoce.
- No es asesoría legal y no sustituye un Acuerdo de Asociado Comercial (BAA) ni a su propio abogado.
- Es nuevo. Hasta hoy solo se ha probado contra su propia aplicación de demostración, todavía no en un producto real dentro de una clínica real. El repositorio enumera cada limitación conocida en una carpeta llamada `things-that-do-not-work`.

**Qué lo haría mejor.** Un proveedor y una organización miembro dispuestos a usarlo juntos y publicar lo que aprendan. Médicos, oficiales de cumplimiento y abogados de salud dispuestos a decirnos dónde las preguntas en lenguaje sencillo están equivocadas.

**Quién está detrás.** Joey Victorino, profesional de seguridad en Henderson, Nevada. github.com/joeyvictorino/patient-zero
