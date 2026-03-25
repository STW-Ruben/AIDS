# AIDS - Autonomous Intrusion Detection System

## Descripción del Proyecto

AIDS (Autonomous Intrusion Detection System) es un sistema de detección de intrusos que desarrollé con el objetivo de monitorear tráfico de red en tiempo real y detectar posibles amenazas de forma automática.

La idea principal del proyecto es simular cómo funcionan los sistemas de seguridad utilizados en entornos reales, pero implementado desde cero utilizando Python. En lugar de depender únicamente de reglas estáticas, el sistema combina dos enfoques: por un lado, detecta ataques conocidos mediante patrones específicos, y por otro, aprende el comportamiento normal de la red para identificar anomalías.

El sistema captura paquetes directamente desde la red, los analiza y va construyendo un perfil de comportamiento para cada dirección IP. A partir de eso, asigna una puntuación de riesgo dependiendo de lo que detecte (por ejemplo: muchos intentos de conexión, escaneos de puertos, tráfico sospechoso, etc.).

Cuando una IP supera cierto nivel de riesgo, el sistema puede tomar acciones automáticamente, como bloquearla o ponerla en cuarentena usando reglas del firewall del sistema.

---

## Objetivo

El objetivo de este proyecto es demostrar cómo se puede construir un sistema básico pero funcional de detección y prevención de intrusos, capaz de:

* Detectar ataques en tiempo real
* Identificar comportamientos anómalos
* Reducir intervención manual mediante automatización
* Aplicar medidas de defensa de forma inmediata

---

## ⚙️ ¿Qué hace el Sistema?

De forma general, el sistema:

* Analiza tráfico en tiempo real
* Detecta múltiples tipos de ataques de red
* Aprende el comportamiento normal de cada IP
* Calcula un “nivel de amenaza” dinámico
* Genera alertas cuando detecta actividad sospechosa
* Puede bloquear o aislar automáticamente una IP

También incluye un panel en consola que muestra en vivo lo que está pasando en la red.

---

## Tipos de Ataques que Detecta

Durante el desarrollo implementé detección para varios escenarios comunes en ciberseguridad, como por ejemplo:

* Ataques de denegación de servicio (como ICMP o SYN flood)
* Escaneos de puertos (como los realizados con herramientas tipo Nmap)
* Intentos de fuerza bruta en servicios como SSH, FTP o RDP
* Ataques de red como ARP spoofing
* Actividad sospechosa en aplicaciones (como SQL injection o XSS)
* Técnicas de evasión (paquetes fragmentados, flags anómalos, etc.)

---

## ¿Cómo funciona internamente?

El sistema sigue una lógica bastante directa:

1. Captura paquetes de red en tiempo real
2. Analiza información como IP origen, puertos, protocolos, etc.
3. Aprende el comportamiento normal de cada IP (baseline)
4. Compara el tráfico actual con ese comportamiento
5. Si detecta algo fuera de lo normal, aumenta su nivel de riesgo
6. Si el riesgo supera ciertos límites:

   * genera una alerta
   * o toma acción (bloqueo o cuarentena)

---

## Tecnologías Utilizadas

* Python 3
* Scapy (para captura y análisis de paquetes)
* iptables (para aplicar bloqueos en el sistema)
* Expresiones regulares (para detectar patrones en tráfico)

---

## Aplicación del Proyecto

Este sistema puede utilizarse en:

* Entornos académicos para aprender sobre ciberseguridad
* Laboratorios de redes
* Simulación de sistemas tipo SOC (Security Operations Center)
* Pruebas básicas de detección de ataques en redes locales

---

## Consideraciones

* El sistema necesita permisos de administrador para funcionar correctamente
* Está pensado principalmente para entornos Linux
* Dependiendo de la configuración, puede generar falsos positivos

---

## Conclusión

Con este proyecto quise demostrar que es posible implementar un sistema funcional de detección de intrusos desde cero, combinando análisis de tráfico, detección de patrones y aprendizaje básico del comportamiento de la red.

Aunque no reemplaza soluciones profesionales, sí sirve como una base sólida para entender cómo funcionan este tipo de herramientas en la práctica.
