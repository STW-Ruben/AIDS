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

## ¿Qué hace el Sistema?

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

## ¿Cómo funciona Internamente?

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

## Instalación

Para utilizar este proyecto, primero debes clonar el repositorio desde GitHub:

```bash
git clone https://github.com/STW-Ruben/AIDS.git
```

Luego accede al directorio del proyecto:

```bash
cd AIDS
```

Instala las dependencias necesarias:

```bash
pip install scapy --break-system-packages
pip install netifaces --break-system-packages
pip install colorama --break-system-packages
pip install tabulate --break-system-packages
```

---

## Ejecución

Ejecuta el sistema con privilegios de administrador (necesario para captura de paquetes y uso de firewall):

```bash
sudo python3 AIDS.py -i <INTERFAZ>
```

Ejemplo:

```bash
sudo python3 AIDS.py -i eth0
```

---

## Modos de Uso

### Modo Normal (Bloqueo Activo)

```bash
sudo python3 AIDS.py -i eth0
```

### Solo Monitoreo (Sin Bloquear)

```bash
sudo python3 AIDS.py --no-block
```

### Configuración Personalizada

```bash
sudo python3 AIDS.py --quarantine-score 40 --block-score 60 --block-time 600
```

### Con Whitelist (Evitar Bloquear Red Local)

```bash
sudo python3 AIDS.py -w 192.168.1.0/24 -j
```

---

## Pruebas

Con el objetivo de demostrar la viabilidad del sistema propuesto, se desarrolló una implementación simplificada utilizando el lenguaje de programación Python, la cual permite simular el comportamiento del modelo AIDS en un entorno real de red. Esta implementación se basa en la captura de tráfico en tiempo real y el análisis de patrones de comportamiento mediante el uso de umbrales, replicando la lógica planteada en el algoritmo teórico.

El sistema desarrollado analiza múltiples protocolos de red, incluyendo ICMP, TCP y UDP, con el fin de identificar posibles comportamientos anómalos como ataques de denegación de servicio, escaneos de puertos y accesos no autorizados. Para ello, se emplea una estructura de contadores por dirección IP, junto con ventanas de tiempo que permiten evaluar la actividad en intervalos específicos, aproximándose al concepto de línea base definido en el modelo original. Inclusive tiene un modo exclusivo para solo monitoreo en caso de no querer bloquear alguna red, y otro modo el cual pone en cuarentena el sistema por si el ataque se detiene, en caso de que no sea así pues bloqueara la red o host que lo este atacando.

Es importante destacar que esta implementación corresponde a una versión simplificada del sistema AIDS, por lo que presenta ciertas limitaciones. En primer lugar, no se incorpora un modelo de aprendizaje automático entrenado con datos reales

### Modo de Solo Monitoreo del AIDS

<img width="1920" height="1200" alt="Image" src="https://github.com/user-attachments/assets/3133184c-ba1b-49dd-9d0d-b2e4771c5a14" />

<img width="1920" height="1200" alt="Image" src="https://github.com/user-attachments/assets/f10f8f8b-2b0d-4283-8932-fe769481a880" />

<img width="1920" height="1200" alt="Image" src="https://github.com/user-attachments/assets/44dcb8b1-55a3-4f07-b67e-f19d3dc1030c" />

<img width="1920" height="1200" alt="Image" src="https://github.com/user-attachments/assets/80ff8405-dea5-4a59-988c-78689e20c5bb" />

<img width="1920" height="1200" alt="Image" src="https://github.com/user-attachments/assets/b453e9cc-c675-436c-9e55-db81fea50899" />

<img width="1920" height="1200" alt="Image" src="https://github.com/user-attachments/assets/73e82eb7-1f00-4878-bd72-cf32b90b7869" />

---
## Requisitos

* Sistema operativo Linux
* Python 3
* Permisos de superusuario (root)
* Interfaz de red válida (eth0, wlan0, etc.)

Para ver tus interfaces disponibles:

```bash
ip a
```
