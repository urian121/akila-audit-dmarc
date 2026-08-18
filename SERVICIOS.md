# Servicios de Akila-DMARC

Akila-DMARC ayuda a que el correo de un dominio (tudominio.com) no pueda ser falsificado —
que nadie pueda mandar un correo haciéndose pasar por tu empresa — y a entender, con datos
reales, quién está mandando correo en tu nombre hoy.

Se divide en dos grandes partes: un **verificador rápido** (para chequear cualquier dominio
al instante, incluso uno que no es tuyo) y un **monitoreo continuo** (para tus propios
dominios, con historial, alertas y reportes reales a lo largo del tiempo).

---

## 1. Verificación rápida de un dominio

La página principal. Escribís un dominio y en unos segundos te dice cómo está configurada su
protección contra suplantación de correo: si tiene SPF, DMARC y DKIM publicados y bien hechos,
si sus servidores de correo (MX) están bien, si tiene DNSSEC activo, y algunos protocolos más
avanzados (DANE, MTA-STS, TLS-RPT, BIMI).

El resultado no es un listado técnico crudo — cada cosa se explica en español simple, con un
semáforo (bien / atención / falla) y, si algo está mal, qué hacer exactamente para arreglarlo,
ordenado del problema más grave al menos grave. También calcula un puntaje general de salud del
dominio (0 a 100%).

Además:

- Un resumen corto generado con inteligencia artificial, como si te lo explicara un analista.
- Descarga del reporte completo en PDF, para mandarlo o archivarlo.
- Una versión de esto mismo disponible como servicio para integrarlo con otras herramientas
  (sin la parte visual, solo los datos).

No hace falta ser dueño del dominio para usar esto — sirve para revisar cualquier dominio,
el propio o el de un cliente/proveedor, y no guarda nada: cada búsqueda es independiente.

## 2. Monitoreo continuo de tus dominios

A diferencia del verificador rápido, esto es para los dominios que administrás vos y querés
vigilar en el tiempo, no solo chequear una vez.

Al registrar un dominio, la aplicación te da las instrucciones exactas de qué agregar en tu DNS
(con un generador interactivo para elegir cuán estricta querés la política, empezando siempre
por el modo más seguro: solo observar, sin bloquear nada) y te deja verificar en vivo si ya
quedó bien publicado.

A partir de ahí, cada dominio registrado tiene su propio panel privado (accesible por un link
único, sin necesidad de compartir usuario ni contraseña — útil para mandárselo a un cliente o
colega) donde se puede:

- Activar o desactivar la vigilancia en cualquier momento sin perder el historial.
- Ver de un vistazo si algún subdominio (facturación, marketing, etc.) está peor configurado
  que el resto.
- Descargar un PDF con el resumen del panel.

Cada cuenta cliente tiene un plan que le dice cuántos dominios puede tener monitoreando **a la
vez**. Hoy hay dos: **Gratis** (1 dominio, con 20 días de prueba) y **Pago** (5 dominios, USD
12/mes). Toda cuenta nueva arranca sola en el plan Gratis apenas se registra — no hace falta pedir
nada. Si se vencen los 20 días y no pasó a Pago, sus dominios se pausan solos (no se borra nada,
es reversible). Pasar a Pago hoy todavía es manual — un administrador lo activa desde el panel de
usuarios después de que la persona pague por otro medio; todavía no hay cobro automático dentro de
la aplicación. Pausar un dominio no borra nada de su historial, así que reactivarlo más adelante no
pierde información, y libera lugar para registrar otro mientras tanto. Las cuentas administradoras
no tienen límite de plan.

## 3. Alertas automáticas

La aplicación revisa sola, cada varias horas, si algo cambió en la configuración de tus
dominios (por ejemplo, si la política DMARC se debilitó, o si cambió el SPF o las firmas DKIM) y
te avisa. También detecta cuándo aparece un remitente que manda correo en tu nombre pero no está
autorizado en tu SPF — no siempre significa un ataque (a veces es solo una herramienta nueva que
falta declarar), pero te lo señala para que lo revises.

Estas alertas se pueden ver agrupadas por organización (para no repetir la misma alerta muchas
veces si es el mismo remitente insistiendo) y filtrar por tipo, fecha o búsqueda, con
paginación si hay muchas.

Si se configura un correo de envío, además de verse en el panel, las alertas se mandan por
email al dueño del dominio.

## 4. Reportes reales de quién manda correo en tu nombre

Los proveedores de correo grandes (Gmail, Outlook, Yahoo, etc.) mandan, una vez al día, un
resumen de qué servidores enviaron correo diciendo ser tu dominio y si esos envíos pasaron la
validación. Akila-DMARC recibe e interpreta esos reportes automáticamente (llegan solos, no hay
que hacer nada manual una vez configurado).

Con esos datos armamos una tabla de **remitentes reales**: cada servidor que mandó correo en tu
nombre, cuántas veces, y si pasó la validación — agrupado por remitente en vez de mostrar el
mismo dato repetido cada día. Se puede filtrar por remitentes que sí tuvieron fallas reales, los
que no, por fecha, o buscar por nombre/IP.

Esta es la fuente de verdad detrás del puntaje de "cumplimiento" de cada dominio: cuánto de tu
correo real está bien autenticado hoy.

## 5. Reportes forenses (el detalle de un fallo puntual)

Además del resumen diario, algunos proveedores mandan un reporte por cada mensaje individual que
falló la validación — casi en el momento en que pasa, no al día siguiente. Es más detallado que
el resumen general, pero muchos proveedores grandes (Gmail, Yahoo) ya no lo mandan por temas de
privacidad, así que no verlo no es un problema de la aplicación.

Por privacidad, acá solo se guarda la información necesaria para investigar el caso (de dónde
vino, a quién iba dirigido, qué falló) — nunca el contenido completo del correo.

## 6. Tendencias y análisis con inteligencia artificial

Una vista dedicada, por dominio, para ver la evolución en el tiempo: cuánto correo se autenticó
bien día por día, comparado en distintos períodos (última semana, mes, tres meses).

Incluye:

- El estado actual de cada protocolo, consultado en vivo.
- Un análisis generado con inteligencia artificial que dice, en lenguaje llano, qué tan sana está
  la autenticación del dominio, qué está bien, qué necesita atención y qué es urgente.
- Un análisis de impacto: si hoy decidieras pasar de "solo observar" a "bloquear correo
  sospechoso", cuánto de tu tráfico legítimo se vería afectado y quiénes son los remitentes que
  todavía fallan — para decidir con datos cuándo es seguro subir el nivel de protección.

## 7. Cumplimiento de todos tus dominios de un vistazo

Pensada para quien administra varios dominios (una marca con distintas subsidiarias, por
ejemplo) y no quiere entrar uno por uno para saber cómo están. Una sola tabla muestra, para cada
dominio: su política actual, qué porcentaje de su correo se autentica bien, y si ya alcanza un
mínimo aceptable de protección o todavía necesita trabajo.

## 8. Historial completo de informes recibidos

Un listado de absolutamente todos los reportes diarios recibidos, de todos tus dominios juntos,
con buscador y filtros (aprobados / con fallas, por fecha). Cada informe se puede abrir para ver
su detalle completo: qué remitentes trajo y cómo les fue.

## 9. Verificación de TLS-RPT

Una vista aparte para confirmar, por cada dominio, si ya quedó publicada la configuración que
permite recibir avisos cuando falla el cifrado del correo entrante (independiente de la
autenticación DMARC/SPF/DKIM).

## 10. Guía de referencia

Una página de documentación en lenguaje simple que explica qué es cada protocolo (DMARC, SPF,
DKIM, y el resto) para quien necesite entender los conceptos antes de tomar una decisión.

## 11. Cuentas y acceso

Cada persona tiene su propia cuenta (registro, inicio de sesión, recuperar/cambiar contraseña,
actualizar el correo) y solo ve los dominios que ella misma registró. Los paneles de monitoreo
por dominio son la excepción a propósito: se comparten por link privado, sin necesitar que la
otra persona tenga cuenta.

Las cuentas administradoras tienen, además, un panel propio con la lista de todas las cuentas de
la aplicación (clientes y otros administradores) — con buscador y filtros — y pueden activar o
desactivar cualquier cuenta. Desactivar a alguien le corta el acceso al instante (aunque ya
tuviera una sesión abierta), pero no borra nada ni afecta sus dominios monitoreados, que siguen
vigilándose igual. Por seguridad, nadie puede desactivarse a sí mismo ni desactivar al último
administrador que quede activo.

Desde ese mismo panel, un administrador también puede cambiarle el plan a cualquier usuario — con
un botón para asignar Gratis o Pago directo, o ajustando a mano el límite de dominios y la fecha
de vencimiento para una excepción puntual. Al vencer un plan sin renovarse, el usuario vuelve solo
al límite por defecto — no hace falta que un admin lo edite a mano para "revertirlo".

Cada cuenta puede tener una **clave de API** para consumir sus datos desde afuera de la
aplicación (un script, otro sistema, un frontend propio) sin tener que iniciar sesión. No es
autogestionable: solo un administrador la genera y la desactiva, eligiendo el usuario desde el
panel — se muestra una sola vez al generarla, así que el admin tiene que copiarla y hacérsela
llegar a esa persona en ese momento. Generar una nueva siempre invalida la anterior al instante.

La lista de usuarios también muestra, de cada cuenta: cuándo se registró, cuándo fue su última
sesión iniciada (o "Nunca" si todavía no entró), si está activa o no, y su plan — toda la
trazabilidad en un solo lugar.

## 12. Descargas en PDF

Tanto el resultado del verificador rápido como el panel de un dominio monitoreado se pueden
descargar como PDF, con el mismo contenido que se ve en pantalla, para compartir o archivar.
