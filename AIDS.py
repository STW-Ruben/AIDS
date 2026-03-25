#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║         AIDS - Autonomous Intrusion Detection System  v4.0                 ║
║         Aprendizaje autónomo · Bloqueo automático · Cuarentena             ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  MOTOR AUTÓNOMO:                                                            ║
║  · Baseline adaptativo  — aprende el tráfico normal de cada IP             ║
║  · Scoring de amenaza   — puntuación acumulada por comportamiento          ║
║  · Auto-bloqueo         — iptables DROP al superar umbral de riesgo        ║
║  · Modo Cuarentena      — aísla la IP: solo permite ICMP para diagnóstico  ║
║  · Auto-desbloqueo      — libera IPs bloqueadas tras tiempo configurable   ║
║  · Panel en vivo        — dashboard que se actualiza cada segundo          ║
║                                                                             ║
║  DETECCIONES:                                                               ║
║  · Floods    : ICMP, SYN, UDP, HTTP/S, DNS, NTP, SSDP, Memcached          ║
║  · Scans     : SYN, FIN, XMAS, NULL, ACK, Window, Maimon                  ║
║  · Bruta     : SSH, FTP, Telnet, RDP, SMB, IMAP, POP3, SMTP, VNC         ║
║  · L2        : ARP Spoofing, ARP Flood, VLAN Hopping, DHCP Rogue          ║
║  · Evasión   : Fragmentación IP, TTL bajo, SYN+FIN ilegal                 ║
║  · Malware   : Backdoors, C2/IRC, Tor, Reverse shell, Shellcode           ║
║  · Infra     : Docker/K8s expuesto, DB expuesta, ICS/SCADA                ║
║  · DPI       : SQLi, XSS, LFI/RFI, cmd injection, creds en claro         ║
║  · IPv6      : RA Flood, NDP Scan, ICMPv6 Flood                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

Uso:
  sudo python3 ids_avanzado.py [opciones]

Opciones:
  -i, --iface     Interfaz (ej: eth0). Default: todas
  -d, --debug     Log DEBUG al archivo (sin mostrar en pantalla)
  -j, --json      Guardar alertas en ids_alerts.jsonl
  -w, --whitelist IPs/subredes excluidas (ej: 192.168.1.1 10.0.0.0/8)
  -t, --ventana   Ventana de análisis en segundos (default: 10)
  -c, --cooldown  Cooldown entre alertas por IP/tipo (default: 30)
  --no-block      Detectar sin bloquear (modo solo observación)
  --block-time    Segundos antes de auto-desbloqueo (default: 300)
  --quarantine-score  Puntuación para cuarentena (default: 80)
  --block-score       Puntuación para bloqueo (default: 50)
"""

# ══════════════════════════════════════════════════════════════════════════════
#  IMPORTS
# ══════════════════════════════════════════════════════════════════════════════

import argparse
import collections
import ipaddress
import json
import logging
import math
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from collections import defaultdict, Counter, deque
from datetime import datetime

try:
    from scapy.all import (
        sniff, Packet,
        Ether, Dot1Q, ARP,
        IP, ICMP, TCP, UDP, Raw,
        IPv6, ICMPv6EchoRequest, ICMPv6ND_RA, ICMPv6ND_NS,
        DNS, DNSQR,
        DHCP,
        conf as scapy_conf,
    )
    scapy_conf.verb = 0
except ImportError:
    print("[FATAL] Scapy no instalado: pip install scapy")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════════════

def _parse_args():
    p = argparse.ArgumentParser(description="AIDS IDS v4.0", add_help=True)
    p.add_argument("-i", "--iface",          default=None)
    p.add_argument("-d", "--debug",          action="store_true")
    p.add_argument("-j", "--json",           action="store_true")
    p.add_argument("-w", "--whitelist",      nargs="*", default=[])
    p.add_argument("-t", "--ventana",        type=int,   default=10)
    p.add_argument("-c", "--cooldown",       type=int,   default=30)
    p.add_argument("--no-block",             action="store_true",
                   help="Solo detectar, nunca bloquear.")
    p.add_argument("--block-time",           type=int,   default=300,
                   help="Segundos hasta auto-desbloqueo (default 300).")
    p.add_argument("--quarantine-score",     type=int,   default=120,
                   help="Score para cuarentena (default 120).")
    p.add_argument("--block-score",          type=int,   default=150,
                   help="Score para bloqueo total (default 150).")
    return p.parse_args()

ARGS = _parse_args()

# ══════════════════════════════════════════════════════════════════════════════
#  CONSTANTES Y CONFIGURACIÓN
# ══════════════════════════════════════════════════════════════════════════════

VENTANA_TIEMPO   = ARGS.ventana
COOLDOWN_ALERTA  = ARGS.cooldown
LOG_FILE         = "ids.log"
JSON_FILE        = "ids_alerts.jsonl"
BASELINE_WINDOW  = 60          # segundos para construir baseline
BASELINE_MIN_PKT = 20          # mínimo de paquetes para considerar baseline válido
SCORE_DECAY_SEC  = 60          # cada cuántos segundos se reduce el score 10%
BLOCK_TIME       = ARGS.block_time
QUARANTINE_SCORE = ARGS.quarantine_score
BLOCK_SCORE      = ARGS.block_score

# Whitelist
WHITELIST_NETS = []
for _e in ARGS.whitelist:
    try:
        WHITELIST_NETS.append(ipaddress.ip_network(_e, strict=False))
    except ValueError:
        pass

# ── Pesos de amenaza por tipo de evento ──────────────────────────────────────
# Cada vez que se detecta un evento se suma este peso al score de la IP.
# El score decae con el tiempo. Bloqueo al superar BLOCK_SCORE.
PESOS = {
    # Críticos (necesitan comportamiento sostenido para bloquear)
    "syn_flood":             30,
    "udp_flood":             25,
    "icmp_flood":            18,
    "nmap_xmas_scan":        25,
    "nmap_null_scan":        25,
    "nmap_fin_scan":         22,
    "tcp_synfin_illegal":    30,
    "tcp_synrst_illegal":    30,
    "tcp_all_flags":         25,
    "arp_spoof_gratuitous":  35,
    "arp_spoof_unsolicited": 30,
    "vlan_hopping":          35,
    "dhcp_starvation":       30,
    "dhcp_rogue_server":     35,
    "sqli_attempt":          35,
    "lfi_rfi":               35,
    "shellcode_tcp":         45,
    "icmp_shellcode":        45,
    "cmd_injection":         40,
    "reverse_shell":         45,
    "ntp_amplification":     30,
    "memcached_amplification": 35,
    "scada_ics_access":      40,
    "scada_udp_access":      40,
    "backdoor_rat":          40,
    "infra_exposed":         35,
    # Altos
    "rdp_brute":             22,
    "ssh_brute":             20,
    "smb_brute":             25,
    "vnc_brute":             20,
    "ftp_brute":             18,
    "telnet_brute":          18,
    "nmap_ack_scan":         14,
    "port_scan":             18,
    "udp_port_scan":         14,
    "dns_zone_transfer":     25,
    "dns_tunnel":            20,
    "icmp_tunnel":           18,
    "ipv6_ra_flood":         30,
    "db_exposed":            22,
    "irc_c2":                25,
    "tor_connection":         8,
    # Medios
    "icmp_redirect":         18,
    "http_flood":            14,
    "https_flood":           14,
    "dns_flood":             10,
    "xss_attempt":           18,
    "http_large_upload":     10,
    "pentest_tool_detected": 22,
    "cleartext_credentials": 12,
    "ldap_enum":             10,
    "rpc_wmi_access":        12,
    "snmp_enumeration":       8,
    "arp_flood":             12,
    "ip_fragmentation":       6,
    "smtp_brute":            12,
    "imap_brute":            10,
    "pop3_brute":            10,
    # Bajos / diagnóstico — NO deben bloquear por sí solos
    "dns_dga":                6,
    "dns_high_entropy":       6,
    "dns_any_query":          3,
    "ntp_flood":              8,
    "tftp_access":            6,
    "mqtt_insecure":          3,
    "chargen_amplification": 14,
    "ssdp_flood":             8,
    "snmp_community_public":  2,
    # Eventos de diagnóstico — peso mínimo, solo informativos
    "ttl_low":                0,   # traceroute normal, nunca penalizar
    "icmp_traceroute":        0,   # traceroute normal
    "os_fingerprint_icmp":    2,   # solo si es realmente repetitivo
    "http_method_suspicious": 4,
    "baseline_anomaly":       5,   # la anomalía sola no bloquea
}

# ── Umbrales de contadores por ventana ───────────────────────────────────────
UMBRALES = {
    "icmp_flood": 30,  "syn_flood": 15,    "udp_flood": 50,
    "conn_excess": 40, "http_flood": 30,   "https_flood": 30,
    "dns_flood": 20,   "ntp_flood": 10,    "ssdp_flood": 10,
    "arp_flood": 15,   "port_scan": 10,
    "nmap_fin": 3,     "nmap_xmas": 3,     "nmap_null": 3,
    "nmap_ack": 5,     "nmap_window": 5,   "nmap_maimon": 3,
    "ssh_brute": 5,    "ftp_brute": 5,     "telnet_brute": 3,
    "rdp_brute": 5,    "smb_brute": 5,
    "imap_brute": 5,   "pop3_brute": 5,    "smtp_brute": 5,
    "vnc_brute": 3,    "ldap_brute": 5,
    "dhcp_discover": 5,"snmp_queries": 5,
    "ip_fragments": 30,"os_fingerprint": 20,
    "dns_tunnel": 1,   "icmp_tunnel": 1,   "large_upload": 3,
    "ipv6_ra_flood": 5,"ipv6_ndp_scan": 10,
}

# ── Tabla de puertos conocidos ────────────────────────────────────────────────
PUERTOS = {
    20:"FTP-Data", 21:"FTP", 22:"SSH", 23:"Telnet", 25:"SMTP",
    53:"DNS", 67:"DHCP-Srv", 68:"DHCP-Cli", 69:"TFTP",
    80:"HTTP", 88:"Kerberos", 110:"POP3", 111:"RPCbind",
    123:"NTP", 135:"RPC/MSRPC", 137:"NetBIOS-NS", 138:"NetBIOS-DGM",
    139:"SMB-NetBIOS", 143:"IMAP", 161:"SNMP", 162:"SNMP-Trap",
    179:"BGP", 194:"IRC", 389:"LDAP", 443:"HTTPS", 445:"SMB",
    464:"Kerberos-PW", 465:"SMTPS", 500:"IKE/IPSec", 502:"Modbus",
    514:"Syslog", 587:"SMTP-TLS", 636:"LDAPS", 873:"rsync",
    902:"VMware", 989:"FTPS-Data", 990:"FTPS", 993:"IMAPS",
    995:"POP3S", 1080:"SOCKS", 1194:"OpenVPN", 1433:"MSSQL",
    1521:"Oracle", 1701:"L2TP", 1723:"PPTP", 1883:"MQTT",
    2049:"NFS", 2200:"SSH-Alt2", 2222:"SSH-Alt",
    2375:"Docker-API", 2376:"Docker-TLS", 2377:"Docker-Swarm",
    3000:"HTTP-Dev", 3128:"Squid-Proxy", 3268:"GlobalCatalog",
    3269:"GlobalCatalog-SSL", 3306:"MySQL", 3389:"RDP",
    4444:"Metasploit", 4445:"MSF-Alt", 4500:"IPSec-NAT",
    4840:"OPC-UA", 5353:"mDNS", 5432:"PostgreSQL",
    5555:"ADB/RAT", 5900:"VNC", 5901:"VNC-1", 5902:"VNC-2",
    5984:"CouchDB", 6379:"Redis", 6443:"Kubernetes-API",
    6667:"IRC", 6697:"IRC-TLS", 7474:"Neo4j", 8000:"HTTP-Dev",
    8001:"K8s-Proxy", 8080:"HTTP-Alt", 8118:"Privoxy",
    8443:"HTTPS-Alt", 8888:"HTTP-Dev2", 9001:"Tor-ORPort",
    9030:"Tor-DirPort", 9042:"Cassandra", 9200:"Elasticsearch",
    9300:"ES-Cluster", 10000:"Webmin", 11211:"Memcached",
    12345:"NetBus", 19:"CHARGEN", 27017:"MongoDB",
    27018:"MongoDB-Shard", 31337:"BackOrifice", 44818:"EtherNet/IP",
    51820:"WireGuard",
}

PUERTOS_BACKDOOR = {4444,4445,5555,6200,7777,12345,31337,1080,6666}
PUERTOS_DB       = {1433,1521,3306,5432,5984,6379,7474,9042,9200,9300,27017,27018}
PUERTOS_SCADA    = {102,502,1883,4840,20000,44818}
PUERTOS_INFRA    = {2375,2376,2377,6443,8001,10000}
PUERTOS_TOR      = {9001,9030}
PUERTOS_IRC      = {194,6667,6697}
PUERTOS_HTTP     = {80,8080,8000,8888,3000}
PUERTOS_HTTPS    = {443,8443}
PUERTOS_SSH      = {22,2222,2200}
PUERTOS_FTP      = {20,21}
PUERTOS_SMTP     = {25,465,587}
PUERTOS_IMAP     = {143,993}
PUERTOS_POP3     = {110,995}
PUERTOS_SMB      = {139,445}
PUERTOS_LDAP     = {389,636,3268,3269}
PUERTOS_VNC      = {5900,5901,5902}

# ── Regex DPI ────────────────────────────────────────────────────────────────
RE_SQLI      = re.compile(rb"(?:union\s+select|'\s*or\s+'?1'?\s*=|drop\s+table|benchmark\s*\(|sleep\s*\(|load_file\s*\(|information_schema)", re.I)
RE_XSS       = re.compile(rb"<\s*script|javascript:|on(?:load|error|click|mouseover)\s*=|eval\s*\(|document\.cookie", re.I)
RE_LFI       = re.compile(rb"(?:\.\.[\\/]){2,}|/etc/passwd|/etc/shadow|(?:php|data|expect|file)://", re.I)
RE_SHELLCODE = re.compile(rb"(?:\\x[0-9a-f]{2}){8,}|\x90{10,}", re.I)
RE_CMDINJ    = re.compile(rb"(?:;|\||\`|\$\()\s*(?:ls|cat|id|whoami|wget|curl|nc|bash|sh|python)", re.I)
RE_REVSHELL  = re.compile(rb"/bin/sh|/bin/bash|cmd\.exe|powershell|nc\s+-e|bash\s+-i", re.I)
RE_PTOOL     = re.compile(rb"sqlmap|nikto|nmap|masscan|dirbuster|gobuster|hydra|metasploit|burpsuite|w3af|acunetix|nessus|ffuf|feroxbuster", re.I)
RE_CREDS     = re.compile(rb"password\s*=|passwd\s*=|pwd\s*=|Authorization:\s*Basic\s+[A-Za-z0-9+/=]{8,}", re.I)

# ══════════════════════════════════════════════════════════════════════════════
#  LOGGING (solo archivo, la consola es el dashboard)
# ══════════════════════════════════════════════════════════════════════════════

def _init_log(logfile: str, debug: bool) -> logging.Logger:
    logger = logging.getLogger("AIDS")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.propagate = False
    fmt = logging.Formatter("%(asctime)s.%(msecs)03d [%(levelname)-8s] %(message)s",
                            datefmt="%Y-%m-%d %H:%M:%S")
    try:
        fh = logging.FileHandler(logfile, encoding="utf-8")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    except OSError:
        pass
    return logger

log: logging.Logger  # se asigna en main()

# ══════════════════════════════════════════════════════════════════════════════
#  MOTOR DE BLOQUEO (iptables)
# ══════════════════════════════════════════════════════════════════════════════

class Firewall:
    """
    Gestiona reglas iptables para bloqueo y cuarentena de IPs.
    Lleva registro de qué se bloqueó y cuándo, para auto-desbloquear.
    """

    CHAIN_BLOCK = "AIDS_BLOCK"
    CHAIN_QUAR  = "AIDS_QUARANTINE"

    def __init__(self, enabled: bool):
        self.enabled   = enabled
        self._lock     = threading.Lock()
        # ip → {"mode": "block"|"quarantine", "ts": float, "razon": str}
        self.bloqueados: dict = {}
        if enabled:
            self._setup_chains()

    def _run(self, args: list) -> bool:
        """Ejecuta un comando iptables; devuelve True si tuvo éxito."""
        try:
            subprocess.run(
                ["iptables"] + args,
                capture_output=True, check=True, timeout=5
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _setup_chains(self):
        """Crea las cadenas personalizadas si no existen."""
        for chain in (self.CHAIN_BLOCK, self.CHAIN_QUAR):
            self._run(["-N", chain])                          # crear (ignora error si ya existe)
            self._run(["-F", chain])                          # limpiar reglas anteriores
        # Enganchar al INPUT principal (idempotente)
        self._run(["-C", "INPUT", "-j", self.CHAIN_BLOCK]) or \
            self._run(["-I", "INPUT", "1", "-j", self.CHAIN_BLOCK])
        self._run(["-C", "INPUT", "-j", self.CHAIN_QUAR]) or \
            self._run(["-I", "INPUT", "2", "-j", self.CHAIN_QUAR])

    def bloquear(self, ip: str, razon: str) -> bool:
        """
        Bloqueo total: DROP de todo tráfico desde la IP.
        """
        if not self.enabled:
            return False
        with self._lock:
            if ip in self.bloqueados:
                return False  # ya bloqueada
            ok = self._run(["-A", self.CHAIN_BLOCK, "-s", ip, "-j", "DROP"])
            if ok:
                self.bloqueados[ip] = {
                    "mode": "block", "ts": time.time(), "razon": razon
                }
                log.warning(f"[FIREWALL-BLOCK] {ip} bloqueado: {razon}")
            return ok

    def cuarentena(self, ip: str, razon: str) -> bool:
        """
        Cuarentena: permite ICMP (diagnóstico) pero bloquea TCP/UDP.
        Útil para aislar un host sin perderlo completamente.
        """
        if not self.enabled:
            return False
        with self._lock:
            if ip in self.bloqueados:
                # Si ya estaba en bloqueo simple, escalar a cuarentena
                if self.bloqueados[ip]["mode"] == "block":
                    return False
            # Bloquear TCP y UDP, permitir ICMP
            ok_tcp = self._run(["-A", self.CHAIN_QUAR, "-s", ip, "-p", "tcp", "-j", "DROP"])
            ok_udp = self._run(["-A", self.CHAIN_QUAR, "-s", ip, "-p", "udp", "-j", "DROP"])
            if ok_tcp or ok_udp:
                self.bloqueados[ip] = {
                    "mode": "quarantine", "ts": time.time(), "razon": razon
                }
                log.warning(f"[FIREWALL-QUARANTINE] {ip} en cuarentena: {razon}")
                return True
            return False

    def desbloquear(self, ip: str) -> bool:
        """Elimina todas las reglas para una IP y la saca del registro."""
        if not self.enabled:
            return False
        with self._lock:
            info = self.bloqueados.pop(ip, None)
            if info is None:
                return False
            # Intentar eliminar de ambas cadenas por seguridad
            if info["mode"] == "block":
                self._run(["-D", self.CHAIN_BLOCK, "-s", ip, "-j", "DROP"])
            else:
                self._run(["-D", self.CHAIN_QUAR, "-s", ip, "-p", "tcp", "-j", "DROP"])
                self._run(["-D", self.CHAIN_QUAR, "-s", ip, "-p", "udp", "-j", "DROP"])
            log.info(f"[FIREWALL-UNBLOCK] {ip} liberado (modo anterior: {info['mode']})")
            return True

    def limpiar_todo(self):
        """Elimina todas las reglas al salir."""
        if not self.enabled:
            return
        with self._lock:
            for ip, info in list(self.bloqueados.items()):
                self.desbloquear(ip)
            for chain in (self.CHAIN_BLOCK, self.CHAIN_QUAR):
                self._run(["-F", chain])
                self._run(["-X", chain])

    def gc_auto_desbloqueo(self):
        """Hilo: comprueba periódicamente si hay IPs que deben liberarse."""
        while True:
            time.sleep(15)
            ahora = time.time()
            with self._lock:
                expiradas = [
                    ip for ip, info in self.bloqueados.items()
                    if ahora - info["ts"] >= BLOCK_TIME
                ]
            for ip in expiradas:
                self.desbloquear(ip)
                log.info(f"[AUTO-UNBLOCK] {ip} liberado tras {BLOCK_TIME}s")

fw: Firewall  # se asigna en main()

# ══════════════════════════════════════════════════════════════════════════════
#  MOTOR DE APRENDIZAJE AUTÓNOMO
# ══════════════════════════════════════════════════════════════════════════════

class PerfilIP:
    """
    Perfil de comportamiento de una IP.

    Fase de aprendizaje (BASELINE_WINDOW segundos):
      — Observa y registra tasas normales de paquetes, bytes, puertos, protocolos.

    Fase de vigilancia:
      — Compara el tráfico actual contra la línea base aprendida.
      — Si una métrica supera N veces la media del baseline → anomalía.
      — Acumula un score de amenaza (0–100+). Decae con el tiempo.
      — Al superar BLOCK_SCORE    → bloqueo.
      — Al superar QUARANTINE_SCORE → cuarentena.
    """

    ANOMALY_FACTOR = 3.0   # cuántas veces la media es "anómalo"

    def __init__(self, ip: str):
        self.ip             = ip
        self.creado         = time.time()
        self.aprendiendo    = True   # True durante el periodo de baseline

        # ── Baseline (ventanas de 1s durante BASELINE_WINDOW s) ──────
        self._bl_pps        = deque()  # paquetes/s observados
        self._bl_bps        = deque()  # bytes/s observados
        self._bl_sports     = deque()  # puertos únicos/ventana
        self._bl_tick_pkts  = 0
        self._bl_tick_bytes = 0
        self._bl_tick_ports : set = set()
        self._bl_last_tick  = time.time()

        # Medias aprendidas
        self.bl_pps_mean    = 0.0
        self.bl_bps_mean    = 0.0
        self.bl_ports_mean  = 0.0

        # ── Contadores ventana actual ─────────────────────────────────
        self._win_start     = time.time()
        self.win_pkts       = 0
        self.win_bytes      = 0
        self.win_puertos: set = set()
        self.win_protos     = Counter()

        # ── Contadores de eventos específicos (se resetean por ventana) ──
        self.icmp = self.syn = self.udp_pkts = self.conn = 0
        self.http = self.https = self.dns = self.ntp = self.ssdp = 0
        self.arp_req = self.fin = self.xmas = 0
        self.null_scan = self.ack = self.window_scan = self.maimon = 0
        self.ssh = self.ftp = self.telnet = self.rdp = self.smb = 0
        self.imap = self.pop3 = self.smtp_auth = self.vnc = self.ldap = 0
        self.fragments = self.os_fp = self.dhcp_disc = self.snmp = 0
        self.dns_tunnel = self.icmp_tunnel = self.large_upload = 0
        self.ipv6_ra = self.ipv6_ndp = 0

        # ── Score de amenaza ──────────────────────────────────────────
        self.score          = 0.0
        self._score_last_decay = time.time()

        # ── Historial de eventos ──────────────────────────────────────
        self.eventos_recientes: deque = deque(maxlen=50)

    # ── Tick de baseline ─────────────────────────────────────────────
    def baseline_tick(self, bytes_pkt: int, dport: int):
        """Llamado por cada paquete durante la fase de aprendizaje."""
        self._bl_tick_pkts  += 1
        self._bl_tick_bytes += bytes_pkt
        self._bl_tick_ports.add(dport)

        ahora = time.time()
        if ahora - self._bl_last_tick >= 1.0:
            self._bl_pps.append(self._bl_tick_pkts)
            self._bl_bps.append(self._bl_tick_bytes)
            self._bl_sports.append(len(self._bl_tick_ports))
            self._bl_tick_pkts  = 0
            self._bl_tick_bytes = 0
            self._bl_tick_ports = set()
            self._bl_last_tick  = ahora

            elapsed = ahora - self.creado
            if elapsed >= BASELINE_WINDOW and sum(self._bl_pps) >= BASELINE_MIN_PKT:
                self._finalizar_baseline()

    def _finalizar_baseline(self):
        """Consolida el baseline y pasa a modo vigilancia."""
        def mean(d): return sum(d) / len(d) if d else 0.0
        self.bl_pps_mean   = mean(self._bl_pps)
        self.bl_bps_mean   = mean(self._bl_bps)
        self.bl_ports_mean = mean(self._bl_sports)
        self.aprendiendo   = False
        log.info(
            f"[BASELINE] {self.ip} aprendido: "
            f"{self.bl_pps_mean:.1f} pps | "
            f"{self.bl_bps_mean:.0f} Bps | "
            f"{self.bl_ports_mean:.1f} puertos/s"
        )

    # ── Detección de anomalía de baseline ───────────────────────────
    def anomalia_baseline(self, pps: float, bps: float, ports: float) -> list[str]:
        """
        Compara métricas actuales contra baseline.
        Devuelve lista de anomalías detectadas.
        """
        if self.aprendiendo or self.bl_pps_mean < 0.1:
            return []
        anomalias = []
        if self.bl_pps_mean > 0 and pps > self.bl_pps_mean * self.ANOMALY_FACTOR:
            anomalias.append(
                f"PPS anómalo: {pps:.1f} vs baseline {self.bl_pps_mean:.1f}"
            )
        if self.bl_bps_mean > 0 and bps > self.bl_bps_mean * self.ANOMALY_FACTOR:
            anomalias.append(
                f"BPS anómalo: {bps:.0f} vs baseline {self.bl_bps_mean:.0f}"
            )
        if self.bl_ports_mean > 0 and ports > self.bl_ports_mean * self.ANOMALY_FACTOR:
            anomalias.append(
                f"Puertos/s anómalo: {ports:.1f} vs baseline {self.bl_ports_mean:.1f}"
            )
        return anomalias

    # ── Score de amenaza ─────────────────────────────────────────────
    def sumar_score(self, tipo: str) -> float:
        """Suma el peso del evento al score y aplica decay. Devuelve score actual."""
        self._aplicar_decay()
        peso = PESOS.get(tipo, 5)
        self.score = min(self.score + peso, 200)  # cap en 200
        self.eventos_recientes.append((time.time(), tipo))
        return self.score

    def _aplicar_decay(self):
        """Reduce el score un 10% cada SCORE_DECAY_SEC segundos."""
        ahora  = time.time()
        pasos  = int((ahora - self._score_last_decay) / SCORE_DECAY_SEC)
        if pasos > 0:
            self.score *= (0.90 ** pasos)
            self._score_last_decay = ahora

    def reset_ventana(self):
        """Reinicia contadores de ventana manteniendo el score."""
        self._win_start  = time.time()
        self.win_pkts    = 0
        self.win_bytes   = 0
        self.win_puertos = set()
        self.win_protos  = Counter()
        self.icmp = self.syn = self.udp_pkts = self.conn = 0
        self.http = self.https = self.dns = self.ntp = self.ssdp = 0
        self.arp_req = self.fin = self.xmas = 0
        self.null_scan = self.ack = self.window_scan = self.maimon = 0
        self.ssh = self.ftp = self.telnet = self.rdp = self.smb = 0
        self.imap = self.pop3 = self.smtp_auth = self.vnc = self.ldap = 0
        self.fragments = self.os_fp = self.dhcp_disc = self.snmp = 0
        self.dns_tunnel = self.icmp_tunnel = self.large_upload = 0
        self.ipv6_ra = self.ipv6_ndp = 0

    @property
    def nivel_amenaza(self) -> str:
        self._aplicar_decay()
        if self.score >= QUARANTINE_SCORE: return "CRITICO"
        if self.score >= BLOCK_SCORE:      return "ALTO"
        if self.score >= 25:               return "MEDIO"
        if self.score >= 10:               return "BAJO"
        return "NORMAL"

    @property
    def estado_firewall(self) -> str:
        info = fw.bloqueados.get(self.ip)
        if info is None:         return "libre"
        if info["mode"] == "block":      return "BLOQUEADO"
        return "CUARENTENA"


# ip → PerfilIP
_perfiles_lock = threading.RLock()
perfiles: dict[str, PerfilIP] = {}

def get_perfil(ip: str) -> PerfilIP:
    with _perfiles_lock:
        if ip not in perfiles:
            perfiles[ip] = PerfilIP(ip)
        return perfiles[ip]

# ══════════════════════════════════════════════════════════════════════════════
#  ESTADO GLOBAL
# ══════════════════════════════════════════════════════════════════════════════

_lock = threading.RLock()

cooldowns: dict = defaultdict(lambda: defaultdict(float))
historial_alertas: list = []
_hist_lock = threading.Lock()

stats = {
    "paquetes_totales": 0,
    "bytes_totales":    0,
    "alertas_totales":  0,
    "ips_unicas":       set(),
    "inicio":           time.time(),
    "proto":            defaultdict(int),
    "acciones":         Counter(),   # block / quarantine / unblock
}

# Cola de eventos para el dashboard (últimas 20 alertas)
_dashboard_eventos: deque = deque(maxlen=20)
_dashboard_lock = threading.Lock()

# ══════════════════════════════════════════════════════════════════════════════
#  UTILIDADES
# ══════════════════════════════════════════════════════════════════════════════

def en_whitelist(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in WHITELIST_NETS)
    except ValueError:
        return False

def puede_alertar(ip: str, tipo: str) -> bool:
    ahora  = time.time()
    ultimo = cooldowns[ip][tipo]
    if ahora - ultimo >= COOLDOWN_ALERTA:
        cooldowns[ip][tipo] = ahora
        return True
    return False

def nombre_puerto(p: int) -> str:
    return PUERTOS.get(p, f"#{p}")

def _entropia(s: str) -> float:
    if len(s) < 4:
        return 0.0
    n   = len(s)
    frq = Counter(s.lower())
    return -sum((c/n)*math.log2(c/n) for c in frq.values())

def alerta(
    ip_src: str, tipo: str, mensaje: str, nivel: str = "WARNING",
    ip_dst: str = "", puerto: int = 0, proto: str = "", extra: dict = None,
) -> None:
    """
    Emite alerta, actualiza score del perfil y decide si bloquear/cuarentenar.
    """
    if not puede_alertar(ip_src, tipo):
        return

    with _lock:
        stats["alertas_totales"] += 1

    # ── Actualizar perfil y score ────────────────────────────────────
    perfil = get_perfil(ip_src)
    score  = perfil.sumar_score(tipo)

    # ── Decidir acción de firewall ────────────────────────────────────
    _decidir_accion_fw(ip_src, perfil, score, tipo, mensaje)

    # ── Registro ──────────────────────────────────────────────────────
    registro = {
        "ts":      datetime.now().isoformat(timespec="milliseconds"),
        "tipo":    tipo,
        "nivel":   nivel,
        "ip_src":  ip_src,
        "ip_dst":  ip_dst,
        "puerto":  puerto,
        "proto":   proto,
        "score":   round(score, 1),
        "mensaje": mensaje,
    }
    if extra:
        registro.update(extra)

    with _hist_lock:
        historial_alertas.append(registro)

    with _dashboard_lock:
        _dashboard_eventos.append(registro)

    if ARGS.json:
        try:
            with open(JSON_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(registro, ensure_ascii=False) + "\n")
        except OSError:
            pass

    # ── Log a archivo ─────────────────────────────────────────────────
    dst_str = f"→{ip_dst}" if ip_dst else ""
    pto_str = f":{puerto}({nombre_puerto(puerto)})" if puerto else ""
    log.log(
        logging.getLevelName(nivel),
        f"[{tipo}][{proto}] {ip_src}{dst_str}{pto_str} score={score:.0f} | {mensaje}",
    )


def _decidir_accion_fw(ip: str, perfil: PerfilIP, score: float, tipo: str, razon: str):
    """Ejecuta bloqueo o cuarentena según score. Escalable."""
    if ARGS.no_block or en_whitelist(ip):
        return
    info = fw.bloqueados.get(ip)
    if info and info["mode"] == "block":
        return  # ya está en el nivel máximo

    if score >= QUARANTINE_SCORE:
        if info and info["mode"] == "quarantine":
            # Escalar cuarentena → bloqueo total
            fw.desbloquear(ip)
            fw.bloquear(ip, f"score={score:.0f} | {razon}")
            stats["acciones"]["block"] += 1
            with _dashboard_lock:
                _dashboard_eventos.append({
                    "ts": datetime.now().isoformat(timespec="milliseconds"),
                    "tipo": "ACCION_BLOQUEO",
                    "nivel": "CRITICAL",
                    "ip_src": ip, "mensaje": f"BLOQUEADO (score={score:.0f})",
                })
        elif info is None:
            fw.cuarentena(ip, f"score={score:.0f} | {razon}")
            stats["acciones"]["quarantine"] += 1
            with _dashboard_lock:
                _dashboard_eventos.append({
                    "ts": datetime.now().isoformat(timespec="milliseconds"),
                    "tipo": "ACCION_CUARENTENA",
                    "nivel": "ERROR",
                    "ip_src": ip, "mensaje": f"EN CUARENTENA (score={score:.0f})",
                })

    elif score >= BLOCK_SCORE and info is None:
        fw.bloquear(ip, f"score={score:.0f} | {razon}")
        stats["acciones"]["block"] += 1
        with _dashboard_lock:
            _dashboard_eventos.append({
                "ts": datetime.now().isoformat(timespec="milliseconds"),
                "tipo": "ACCION_BLOQUEO",
                "nivel": "CRITICAL",
                "ip_src": ip, "mensaje": f"BLOQUEADO (score={score:.0f})",
            })

# ══════════════════════════════════════════════════════════════════════════════
#  DASHBOARD EN TIEMPO REAL
# ══════════════════════════════════════════════════════════════════════════════

_COLORES = {
    "CRITICO":    "\033[1;91m",
    "ALTO":       "\033[91m",
    "MEDIO":      "\033[93m",
    "BAJO":       "\033[96m",
    "NORMAL":     "\033[37m",
    "RESET":      "\033[0m",
    "BOLD":       "\033[1m",
    "DIM":        "\033[2m",
    "GREEN":      "\033[92m",
    "YELLOW":     "\033[93m",
    "RED":        "\033[91m",
    "CYAN":       "\033[96m",
    "WHITE":      "\033[97m",
    "BG_RED":     "\033[41m",
    "BG_YELLOW":  "\033[43m",
    "BG_BLUE":    "\033[44m",
}
C = _COLORES

_NIVEL_COLOR = {
    "CRITICAL": C["RED"],   "ERROR": C["RED"],
    "WARNING":  C["YELLOW"],"INFO":  C["WHITE"],
    "ACCION_BLOQUEO":     C["BG_RED"] + C["WHITE"],
    "ACCION_CUARENTENA":  C["BG_YELLOW"] + C["WHITE"],
}

def _color_nivel(nivel: str) -> str:
    return _NIVEL_COLOR.get(nivel, C["RESET"])

def _color_amenaza(nivel: str) -> str:
    return C.get(nivel, C["RESET"])

def _barra(valor: float, maximo: float, ancho: int = 10) -> str:
    if maximo <= 0:
        return "░" * ancho
    lleno = int(min(valor / maximo, 1.0) * ancho)
    return "█" * lleno + "░" * (ancho - lleno)


def _render_dashboard():
    """
    Dibuja el dashboard completo en la terminal.
    Usa secuencias ANSI para limpiar y sobreescribir en lugar de hacer scroll.
    """
    ahora  = time.time()
    uptime = int(ahora - stats["inicio"])
    hh, mm, ss = uptime//3600, (uptime%3600)//60, uptime%60

    bps = stats["bytes_totales"] / max(uptime, 1)
    pps = stats["paquetes_totales"] / max(uptime, 1)

    # Top 8 IPs más activas por score
    with _perfiles_lock:
        top_ips = sorted(
            [(ip, p) for ip, p in perfiles.items()],
            key=lambda x: x[1].score,
            reverse=True,
        )[:8]

    # Últimas 10 alertas
    with _dashboard_lock:
        ultimas = list(_dashboard_eventos)[-10:]

    # Bloqueados activos
    with fw._lock:
        bloqueados_snap = dict(fw.bloqueados)

    # ── Construir pantalla ────────────────────────────────────────────
    lineas = []
    W = 80  # ancho fijo

    def sep(c="═"):
        return c * W

    def titulo(t, c="─"):
        pad = (W - len(t) - 2) // 2
        return f"{c*pad} {t} {c*(W-pad-len(t)-2)}"

    # Cabecera
    lineas.append(f"{C['BOLD']}{C['CYAN']}")
    lineas.append(sep())
    lineas.append(
        f"  AIDS v4.0 · Autonomous IDS  │  "
        f"⏱ {hh:02d}:{mm:02d}:{ss:02d}  │  "
        f"{'⛔ SOLO OBSERVACIÓN' if ARGS.no_block else '🔒 PROTECCIÓN ACTIVA'}"
    )
    lineas.append(sep())
    lineas.append(C["RESET"])

    # Stats globales
    lineas.append(
        f"  Pkts: {C['WHITE']}{stats['paquetes_totales']:>10,}{C['RESET']}  "
        f"Bytes: {C['WHITE']}{stats['bytes_totales']:>12,}{C['RESET']}  "
        f"Avg: {C['WHITE']}{pps:>6.1f}pps {bps:>8.0f}B/s{C['RESET']}"
    )
    lineas.append(
        f"  Alertas: {C['YELLOW']}{stats['alertas_totales']:>6}{C['RESET']}  "
        f"IPs vistas: {C['WHITE']}{len(stats['ips_unicas']):>5}{C['RESET']}  "
        f"Bloqueadas: {C['RED']}{len(bloqueados_snap):>4}{C['RESET']}  "
        f"Acciones: bloqueo={C['RED']}{stats['acciones']['block']}{C['RESET']} "
        f"cuarentena={C['YELLOW']}{stats['acciones']['quarantine']}{C['RESET']}"
    )

    # Top protocolos
    top_proto = sorted(stats["proto"].items(), key=lambda x: -x[1])[:6]
    proto_str = "  ".join(f"{k}:{v:,}" for k, v in top_proto)
    lineas.append(f"  Proto: {C['DIM']}{proto_str}{C['RESET']}")
    lineas.append("")

    # ── Top IPs por score ─────────────────────────────────────────────
    lineas.append(f"{C['BOLD']}{titulo('TOP IPs POR SCORE DE AMENAZA')}{C['RESET']}")
    lineas.append(
        f"  {'IP':<18} {'Score':>6}  {'Nivel':<8}  "
        f"{'Barra':<12}  {'Estado FW':<12}  Último evento"
    )
    lineas.append("  " + "─"*(W-2))

    for ip, p in top_ips:
        p._aplicar_decay()
        c_nivel = _color_amenaza(p.nivel_amenaza)
        barra   = _barra(p.score, 100)
        estado  = p.estado_firewall
        c_estado = C["RED"] if estado != "libre" else C["DIM"]
        ult_ev  = p.eventos_recientes[-1][1] if p.eventos_recientes else "—"
        aprendiz = "📚" if p.aprendiendo else ""
        lineas.append(
            f"  {ip:<18} {c_nivel}{p.score:>6.1f}{C['RESET']}  "
            f"{c_nivel}{p.nivel_amenaza:<8}{C['RESET']}  "
            f"{barra:<12}  {c_estado}{estado:<12}{C['RESET']}  "
            f"{C['DIM']}{ult_ev[:20]}{C['RESET']} {aprendiz}"
        )

    # Relleno si hay menos de 8
    for _ in range(max(0, 8 - len(top_ips))):
        lineas.append(f"  {'—':<18}")

    lineas.append("")

    # ── IPs en cuarentena/bloqueo ─────────────────────────────────────
    if bloqueados_snap:
        lineas.append(f"{C['BOLD']}{titulo('HOSTS AISLADOS', '─')}{C['RESET']}")
        for ip, info in list(bloqueados_snap.items())[:5]:
            elapsed = int(ahora - info["ts"])
            restante = max(0, BLOCK_TIME - elapsed)
            modo_color = C["BG_RED"]+C["WHITE"] if info["mode"]=="block" else C["BG_YELLOW"]+C["WHITE"]
            razon_short = info["razon"][:38]
            lineas.append(
                f"  {modo_color} {info['mode'].upper():<11} {C['RESET']} "
                f"{ip:<18} ⏳{restante:>4}s restantes  {C['DIM']}{razon_short}{C['RESET']}"
            )
        lineas.append("")

    # ── Últimas alertas ───────────────────────────────────────────────
    lineas.append(f"{C['BOLD']}{titulo('ÚLTIMAS ALERTAS')}{C['RESET']}")
    for ev in reversed(ultimas):
        ts_short  = ev.get("ts", "")[-12:]
        tipo_ev   = ev.get("tipo", "")[:20]
        ip_ev     = ev.get("ip_src", "")
        msg_ev    = ev.get("mensaje", "")[:35]
        nivel_ev  = ev.get("nivel", "INFO")
        c_ev      = _color_nivel(nivel_ev)
        lineas.append(
            f"  {C['DIM']}{ts_short}{C['RESET']}  "
            f"{c_ev}{tipo_ev:<22}{C['RESET']}  "
            f"{ip_ev:<18}  {C['DIM']}{msg_ev}{C['RESET']}"
        )

    # Relleno
    for _ in range(max(0, 10 - len(ultimas))):
        lineas.append("")

    lineas.append(sep())
    lineas.append(
        f"  {C['DIM']}Ctrl+C para salir  │  "
        f"--no-block para solo observar  │  "
        f"--help para opciones{C['RESET']}"
    )
    lineas.append(sep())

    # ── Renderizar: mover cursor al inicio y sobreescribir ────────────
    # \033[H  = mover al inicio  |  \033[J = limpiar hacia abajo
    salida = "\033[H\033[J" + "\n".join(lineas) + "\n"
    sys.stdout.write(salida)
    sys.stdout.flush()


def _hilo_dashboard():
    """Refresca el dashboard cada segundo."""
    # Ocultar cursor
    sys.stdout.write("\033[?25l")
    sys.stdout.flush()
    while True:
        try:
            _render_dashboard()
        except Exception:
            pass
        time.sleep(1.0)


# ══════════════════════════════════════════════════════════════════════════════
#  DISPATCHER PRINCIPAL
# ══════════════════════════════════════════════════════════════════════════════

def analizar(pkt: Packet) -> None:
    with _lock:
        pkt_len = len(pkt)
        stats["paquetes_totales"] += 1
        stats["bytes_totales"]    += pkt_len

        if pkt.haslayer(ARP):
            stats["proto"]["ARP"] += 1
            _analizar_arp(pkt)

        if pkt.haslayer(Dot1Q):
            _analizar_vlan(pkt)

        if pkt.haslayer(IP):
            ip = pkt[IP]
            if en_whitelist(ip.src):
                return
            stats["ips_unicas"].add(ip.src)
            stats["proto"]["IPv4"] += 1

            perfil = get_perfil(ip.src)
            perfil.win_pkts   += 1
            perfil.win_bytes  += pkt_len

            # Fase de aprendizaje
            dport_hint = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
            if perfil.aprendiendo:
                perfil.baseline_tick(pkt_len, dport_hint)

            # Comprobar si la ventana expiró
            if time.time() - perfil._win_start >= VENTANA_TIEMPO:
                _evaluar_baseline_anomaly(perfil, ip.src)
                perfil.reset_ventana()

            _analizar_ip4(pkt, perfil)

        elif pkt.haslayer(IPv6):
            stats["proto"]["IPv6"] += 1
            ip6 = pkt[IPv6]
            if not en_whitelist(ip6.src):
                _analizar_ip6(pkt)


def _evaluar_baseline_anomaly(perfil: PerfilIP, ip: str):
    """Compara ventana actual con baseline y emite alertas si hay anomalías."""
    if perfil.aprendiendo:
        return
    elapsed = max(time.time() - perfil._win_start, 1)
    pps_act = perfil.win_pkts   / elapsed
    bps_act = perfil.win_bytes  / elapsed
    pts_act = len(perfil.win_puertos) / elapsed

    anomalias = perfil.anomalia_baseline(pps_act, bps_act, pts_act)
    for msg in anomalias:
        alerta(ip, "baseline_anomaly",
               f"Anomalía de comportamiento detectada: {msg}",
               "WARNING", proto="AUTONOMO")

# ══════════════════════════════════════════════════════════════════════════════
#  ARP
# ══════════════════════════════════════════════════════════════════════════════

def _analizar_arp(pkt):
    arp    = pkt[ARP]
    ip_src = arp.psrc
    ip_dst = arp.pdst
    mac    = arp.hwsrc
    if en_whitelist(ip_src):
        return
    perfil = get_perfil(ip_src)

    if arp.op == 1:
        perfil.arp_req += 1
        if perfil.arp_req > UMBRALES["arp_flood"]:
            alerta(ip_src, "arp_flood",
                   f"ARP Flood/Scan ({perfil.arp_req} requests en {VENTANA_TIEMPO}s)",
                   "ERROR", proto="ARP")
    elif arp.op == 2:
        if ip_src == ip_dst:
            alerta(ip_src, "arp_spoof_gratuitous",
                   f"Gratuitous ARP desde {ip_src} MAC:{mac} → ARP Spoofing/MITM",
                   "CRITICAL", proto="ARP")
        elif perfil.arp_req == 0:
            alerta(ip_src, "arp_spoof_unsolicited",
                   f"ARP Reply no solicitado {ip_src} MAC:{mac}",
                   "ERROR", proto="ARP")

def _analizar_vlan(pkt):
    outer = pkt[Dot1Q]
    if isinstance(outer.payload, Dot1Q):
        mac = pkt[Ether].src if pkt.haslayer(Ether) else "??"
        alerta(f"L2:{mac}", "vlan_hopping",
               f"VLAN Hopping (double-tag 802.1Q) MAC:{mac}",
               "CRITICAL", proto="802.1Q")

# ══════════════════════════════════════════════════════════════════════════════
#  IPv4
# ══════════════════════════════════════════════════════════════════════════════

def _analizar_ip4(pkt, perfil: PerfilIP):
    ip     = pkt[IP]
    ip_src = ip.src
    ip_dst = ip.dst

    # Fragmentación
    if (ip.flags & 0x1) or ip.frag > 0:
        perfil.fragments += 1
        if perfil.fragments > UMBRALES["ip_fragments"]:
            alerta(ip_src, "ip_fragmentation",
                   f"Fragmentación IP excesiva ({perfil.fragments} frags) → evasión IDS",
                   "WARNING", ip_dst=ip_dst, proto="IPv4")

    # TTL bajo: solo penalizar si no es un TTL de traceroute (1-30)
    # y el paquete NO es ICMP (traceroute usa ICMP con TTL incremental)
    if 0 < ip.ttl <= 5 and not pkt.haslayer(ICMP):
        perfil.os_fp += 1
        if perfil.os_fp > UMBRALES["os_fingerprint"]:
            alerta(ip_src, "ttl_low",
                   f"TTL extremadamente bajo ({ip.ttl}) en tráfico no-ICMP → evasión/anomalía",
                   "WARNING", ip_dst=ip_dst, proto="IPv4")

    if pkt.haslayer(ICMP):
        stats["proto"]["ICMP"] += 1
        _analizar_icmp(pkt, perfil, ip_src, ip_dst)
    if pkt.haslayer(TCP):
        stats["proto"]["TCP"] += 1
        _analizar_tcp(pkt, perfil, ip_src, ip_dst)
    if pkt.haslayer(UDP):
        stats["proto"]["UDP"] += 1
        _analizar_udp(pkt, perfil, ip_src, ip_dst)

# ══════════════════════════════════════════════════════════════════════════════
#  IPv6
# ══════════════════════════════════════════════════════════════════════════════

def _analizar_ip6(pkt):
    ip6    = pkt[IPv6]
    ip_src = ip6.src
    ip_dst = ip6.dst
    perfil = get_perfil(ip_src)

    if pkt.haslayer(ICMPv6EchoRequest):
        perfil.icmp += 1
        stats["proto"]["ICMPv6"] += 1
        if perfil.icmp > UMBRALES["icmp_flood"]:
            alerta(ip_src, "icmpv6_echo_flood",
                   f"ICMPv6 Echo Flood ({perfil.icmp} en {VENTANA_TIEMPO}s)",
                   "ERROR", ip_dst=ip_dst, proto="ICMPv6")

    if pkt.haslayer(ICMPv6ND_RA):
        perfil.ipv6_ra += 1
        stats["proto"]["ICMPv6-RA"] += 1
        if perfil.ipv6_ra > UMBRALES["ipv6_ra_flood"]:
            alerta(ip_src, "ipv6_ra_flood",
                   f"IPv6 RA Flood ({perfil.ipv6_ra} RA) → NDP Poisoning",
                   "CRITICAL", ip_dst=ip_dst, proto="ICMPv6")

    if pkt.haslayer(ICMPv6ND_NS):
        perfil.ipv6_ndp += 1
        if perfil.ipv6_ndp > UMBRALES["ipv6_ndp_scan"]:
            alerta(ip_src, "ipv6_ndp_scan",
                   f"NDP Scan ({perfil.ipv6_ndp} NS en {VENTANA_TIEMPO}s)",
                   "ERROR", ip_dst=ip_dst, proto="ICMPv6")

    if pkt.haslayer(TCP):
        stats["proto"]["TCPv6"] += 1
        _analizar_tcp(pkt, perfil, ip_src, ip_dst, is_ipv6=True)
    if pkt.haslayer(UDP):
        stats["proto"]["UDPv6"] += 1
        _analizar_udp(pkt, perfil, ip_src, ip_dst, is_ipv6=True)

# ══════════════════════════════════════════════════════════════════════════════
#  ICMP
# ══════════════════════════════════════════════════════════════════════════════

def _analizar_icmp(pkt, perfil: PerfilIP, ip_src: str, ip_dst: str):
    icmp = pkt[ICMP]
    ttl  = pkt[IP].ttl

    # ── Traceroute: TTL ≤ 30 + Echo Request → diagnóstico legítimo ──────────
    # Un traceroute manda paquetes con TTL=1,2,3... y genera Time-Exceeded
    # de vuelta. No es un ataque — ignorar para el score completamente.
    es_traceroute = (icmp.type == 8 and ttl <= 30)

    if icmp.type == 8:  # Echo Request
        if not es_traceroute:
            perfil.icmp += 1
            if perfil.icmp > UMBRALES["icmp_flood"]:
                alerta(ip_src, "icmp_flood",
                       f"Ping Flood ({perfil.icmp} echo-req en {VENTANA_TIEMPO}s)",
                       "ERROR", ip_dst=ip_dst, proto="ICMP")
        else:
            # Solo log debug, sin score, sin alerta
            log.debug(f"[TRACEROUTE] {ip_src} → {ip_dst} TTL={ttl} (diagnóstico, ignorado)")

    elif icmp.type == 5:  # Redirect → sí es peligroso
        alerta(ip_src, "icmp_redirect",
               f"ICMP Redirect (code={icmp.code}) → posible envenenamiento de rutas/MITM",
               "CRITICAL", ip_dst=ip_dst, proto="ICMP")

    elif icmp.type == 11:  # Time Exceeded → respuesta a traceroute, ignorar
        log.debug(f"[TRACEROUTE-TTL-EXC] {ip_src} → {ip_dst} (respuesta normal a traceroute)")

    elif icmp.type == 30:  # Traceroute ICMP explícito — solo info, sin score
        alerta(ip_src, "icmp_traceroute",
               f"Traceroute ICMP hacia {ip_dst}", "INFO", ip_dst=ip_dst, proto="ICMP")

    # ── Payload sospechoso (tunneling / shellcode) ────────────────────────────
    if pkt.haslayer(Raw):
        pl = pkt[Raw].load
        # Túnel ICMP: payload mucho más grande de lo normal (ping normal = 32-64B)
        if len(pl) > 500:
            perfil.icmp_tunnel += 1
            alerta(ip_src, "icmp_tunnel",
                   f"Payload ICMP muy grande ({len(pl)}B, normal ≤ 64B) → posible tunneling",
                   "WARNING", ip_dst=ip_dst, proto="ICMP")
        if RE_SHELLCODE.search(pl):
            alerta(ip_src, "icmp_shellcode",
                   "Shellcode/NOP-sled en payload ICMP", "CRITICAL", ip_dst=ip_dst, proto="ICMP")

    # ── OS fingerprinting via TTL: solo si TTL es REALMENTE inusual ──────────
    # No penalizar TTL bajo de traceroute (1-30). Penalizar solo valores
    # como 0, 31-54, 131-254 que no corresponden a ningún SO ni traceroute.
    ttl_sospechoso = ttl == 0 or (30 < ttl < 55) or (130 < ttl < 255)
    if ttl_sospechoso and not es_traceroute:
        perfil.os_fp += 1
        if perfil.os_fp > UMBRALES["os_fingerprint"]:
            alerta(ip_src, "os_fingerprint_icmp",
                   f"TTL inusual en ICMP ({ttl}) → posible OS fingerprinting activo",
                   "WARNING", ip_dst=ip_dst, proto="ICMP")

# ══════════════════════════════════════════════════════════════════════════════
#  TCP
# ══════════════════════════════════════════════════════════════════════════════

def _analizar_tcp(pkt, perfil: PerfilIP, ip_src: str, ip_dst: str, is_ipv6=False):
    tcp   = pkt[TCP]
    dport = tcp.dport
    sport = tcp.sport
    flags = int(tcp.flags)
    proto = "TCPv6" if is_ipv6 else "TCP"

    perfil.conn += 1
    perfil.win_puertos.add(dport)

    # ── Flags anómalos ───────────────────────────────────────────────
    if   flags == 0x02: _flag_syn(perfil, ip_src, ip_dst, dport, tcp, proto)
    elif flags == 0x01: _flag_fin(perfil, ip_src, ip_dst, dport, proto)
    elif flags == 0x29: _flag_xmas(perfil, ip_src, ip_dst, dport, proto)
    elif flags == 0x00: _flag_null(perfil, ip_src, ip_dst, dport, proto)
    elif flags == 0x10: _flag_ack(perfil, ip_src, ip_dst, dport, tcp, proto)
    elif flags == 0x11: _flag_maimon(perfil, ip_src, ip_dst, dport, proto)

    if (flags & 0x03) == 0x03:
        alerta(ip_src, "tcp_synfin_illegal",
               "SYN+FIN ilegal (RFC793) → evasión firewall",
               "CRITICAL", ip_dst=ip_dst, puerto=dport, proto=proto)
    if (flags & 0x06) == 0x06:
        alerta(ip_src, "tcp_synrst_illegal",
               "SYN+RST ilegal → fuzzing/evasión",
               "ERROR", ip_dst=ip_dst, puerto=dport, proto=proto)
    if flags >= 0xBF:
        alerta(ip_src, "tcp_all_flags",
               f"Todos los flags TCP activos (0x{flags:02X}) → fuzzer",
               "ERROR", ip_dst=ip_dst, puerto=dport, proto=proto)

    # ── Port Scan ────────────────────────────────────────────────────
    n_ports = len(perfil.win_puertos)
    if n_ports > UMBRALES["port_scan"]:
        alerta(ip_src, "port_scan",
               f"Port Scan ({n_ports} puertos únicos en {VENTANA_TIEMPO}s)",
               "ERROR", ip_dst=ip_dst, proto=proto)

    if perfil.conn > UMBRALES["conn_excess"]:
        alerta(ip_src, "conn_excess",
               f"Exceso de conexiones TCP ({perfil.conn})",
               "WARNING", ip_dst=ip_dst, proto=proto)

    # ── Servicios específicos ────────────────────────────────────────
    _servicio_tcp(pkt, perfil, ip_src, ip_dst, dport, flags, proto)

    # ── DPI payload ──────────────────────────────────────────────────
    if pkt.haslayer(Raw):
        _dpi_tcp(pkt[Raw].load, perfil, ip_src, ip_dst, dport, proto)

# ── Sub-funciones de flags ────────────────────────────────────────────────────

def _flag_syn(perfil, ip_src, ip_dst, dport, tcp, proto):
    perfil.syn += 1
    if perfil.syn > UMBRALES["syn_flood"]:
        alerta(ip_src, "syn_flood",
               f"SYN Flood ({perfil.syn} SYNs en {VENTANA_TIEMPO}s)",
               "CRITICAL", ip_dst=ip_dst, puerto=dport, proto=proto)

def _flag_fin(perfil, ip_src, ip_dst, dport, proto):
    perfil.fin += 1
    if perfil.fin > UMBRALES["nmap_fin"]:
        alerta(ip_src, "nmap_fin_scan",
               f"Nmap FIN Scan ({perfil.fin} pqts FIN)",
               "ERROR", ip_dst=ip_dst, puerto=dport, proto=proto)

def _flag_xmas(perfil, ip_src, ip_dst, dport, proto):
    perfil.xmas += 1
    if perfil.xmas > UMBRALES["nmap_xmas"]:
        alerta(ip_src, "nmap_xmas_scan",
               f"Nmap XMAS Scan (FIN+PSH+URG, {perfil.xmas} pqts)",
               "ERROR", ip_dst=ip_dst, puerto=dport, proto=proto)

def _flag_null(perfil, ip_src, ip_dst, dport, proto):
    perfil.null_scan += 1
    if perfil.null_scan > UMBRALES["nmap_null"]:
        alerta(ip_src, "nmap_null_scan",
               f"Nmap NULL Scan ({perfil.null_scan} pqts sin flags)",
               "ERROR", ip_dst=ip_dst, puerto=dport, proto=proto)

def _flag_ack(perfil, ip_src, ip_dst, dport, tcp, proto):
    perfil.ack += 1
    if perfil.ack > UMBRALES["nmap_ack"]:
        alerta(ip_src, "nmap_ack_scan",
               f"Nmap ACK Scan / Firewall Mapping ({perfil.ack} pqts)",
               "WARNING", ip_dst=ip_dst, puerto=dport, proto=proto)
    if tcp.window != 0 and perfil.ack > UMBRALES["nmap_window"]:
        alerta(ip_src, "nmap_window_scan",
               f"Nmap Window Scan ({perfil.ack} pqts, win={tcp.window})",
               "WARNING", ip_dst=ip_dst, puerto=dport, proto=proto)

def _flag_maimon(perfil, ip_src, ip_dst, dport, proto):
    perfil.maimon += 1
    if perfil.maimon > UMBRALES["nmap_maimon"]:
        alerta(ip_src, "nmap_maimon_scan",
               f"Nmap Maimon Scan (FIN+ACK, {perfil.maimon} pqts)",
               "WARNING", ip_dst=ip_dst, puerto=dport, proto=proto)

def _servicio_tcp(pkt, perfil, ip_src, ip_dst, dport, flags, proto):
    """Detecciones por servicio/puerto."""
    if dport in PUERTOS_SSH:
        perfil.ssh += 1
        if perfil.ssh > UMBRALES["ssh_brute"]:
            alerta(ip_src, "ssh_brute",
                   f"Fuerza bruta SSH ({perfil.ssh} intentos)",
                   "CRITICAL", ip_dst=ip_dst, puerto=dport, proto=proto)
    elif dport == 23:
        perfil.telnet += 1
        if perfil.telnet > UMBRALES["telnet_brute"]:
            alerta(ip_src, "telnet_brute",
                   f"Bruta Telnet ({perfil.telnet}) → sin cifrado",
                   "ERROR", ip_dst=ip_dst, puerto=23, proto=proto)
    elif dport in PUERTOS_FTP:
        perfil.ftp += 1
        if perfil.ftp > UMBRALES["ftp_brute"]:
            alerta(ip_src, "ftp_brute",
                   f"Fuerza bruta FTP ({perfil.ftp})",
                   "ERROR", ip_dst=ip_dst, puerto=dport, proto=proto)
    elif dport in PUERTOS_SMTP:
        perfil.smtp_auth += 1
        if perfil.smtp_auth > UMBRALES["smtp_brute"]:
            alerta(ip_src, "smtp_brute",
                   f"Bruta SMTP ({perfil.smtp_auth})",
                   "WARNING", ip_dst=ip_dst, puerto=dport, proto=proto)
    elif dport in PUERTOS_HTTP:
        perfil.http += 1
        if perfil.http > UMBRALES["http_flood"]:
            alerta(ip_src, "http_flood",
                   f"HTTP Flood ({perfil.http} req en {VENTANA_TIEMPO}s)",
                   "ERROR", ip_dst=ip_dst, puerto=dport, proto=proto)
    elif dport in PUERTOS_HTTPS:
        perfil.https += 1
        if perfil.https > UMBRALES["https_flood"]:
            alerta(ip_src, "https_flood",
                   f"HTTPS Flood ({perfil.https} req en {VENTANA_TIEMPO}s)",
                   "ERROR", ip_dst=ip_dst, puerto=dport, proto=proto)
    elif dport in PUERTOS_IMAP:
        perfil.imap += 1
        if perfil.imap > UMBRALES["imap_brute"]:
            alerta(ip_src, "imap_brute",
                   f"Bruta IMAP ({perfil.imap})",
                   "WARNING", ip_dst=ip_dst, puerto=dport, proto=proto)
    elif dport in PUERTOS_POP3:
        perfil.pop3 += 1
        if perfil.pop3 > UMBRALES["pop3_brute"]:
            alerta(ip_src, "pop3_brute",
                   f"Bruta POP3 ({perfil.pop3})",
                   "WARNING", ip_dst=ip_dst, puerto=dport, proto=proto)
    elif dport == 3389:
        perfil.rdp += 1
        if perfil.rdp > UMBRALES["rdp_brute"]:
            alerta(ip_src, "rdp_brute",
                   f"Fuerza bruta RDP ({perfil.rdp}) → BlueKeep/DejaBlue",
                   "CRITICAL", ip_dst=ip_dst, puerto=3389, proto=proto)
    elif dport in PUERTOS_SMB:
        perfil.smb += 1
        if perfil.smb > UMBRALES["smb_brute"]:
            alerta(ip_src, "smb_brute",
                   f"Ataque SMB ({perfil.smb}) → EternalBlue/PtH/Relay",
                   "CRITICAL", ip_dst=ip_dst, puerto=dport, proto=proto)
    elif dport in PUERTOS_LDAP:
        perfil.ldap += 1
        if perfil.ldap > UMBRALES["ldap_brute"]:
            alerta(ip_src, "ldap_enum",
                   f"LDAP Enumeration ({perfil.ldap}) → AD recon/Kerberoasting",
                   "WARNING", ip_dst=ip_dst, puerto=dport, proto=proto)
    elif dport in PUERTOS_VNC:
        perfil.vnc += 1
        if perfil.vnc > UMBRALES["vnc_brute"]:
            alerta(ip_src, "vnc_brute",
                   f"Fuerza bruta VNC ({perfil.vnc})",
                   "ERROR", ip_dst=ip_dst, puerto=dport, proto=proto)
    elif dport == 135:
        alerta(ip_src, "rpc_wmi_access",
               "Acceso RPC/WMI → movimiento lateral (PsExec/DCOM)",
               "WARNING", ip_dst=ip_dst, puerto=135, proto=proto)
    elif dport in PUERTOS_IRC:
        alerta(ip_src, "irc_c2",
               f"IRC en puerto {dport} → botnet C2",
               "ERROR", ip_dst=ip_dst, puerto=dport, proto=proto)
    elif dport in PUERTOS_TOR:
        alerta(ip_src, "tor_connection",
               f"Nodo Tor (puerto {dport}) → anonimización/C2",
               "WARNING", ip_dst=ip_dst, puerto=dport, proto=proto)
    elif dport in PUERTOS_BACKDOOR:
        alerta(ip_src, "backdoor_rat",
               f"Puerto backdoor/RAT: {dport} ({nombre_puerto(dport)})",
               "CRITICAL", ip_dst=ip_dst, puerto=dport, proto=proto)
    elif dport in PUERTOS_INFRA:
        alerta(ip_src, "infra_exposed",
               f"Infraestructura expuesta: {dport} ({nombre_puerto(dport)})",
               "CRITICAL", ip_dst=ip_dst, puerto=dport, proto=proto)
    elif dport in PUERTOS_DB:
        alerta(ip_src, "db_exposed",
               f"BD expuesta: {nombre_puerto(dport)} ({dport})",
               "ERROR", ip_dst=ip_dst, puerto=dport, proto=proto)
    elif dport in PUERTOS_SCADA:
        alerta(ip_src, "scada_ics_access",
               f"ICS/SCADA: {nombre_puerto(dport)} ({dport})",
               "CRITICAL", ip_dst=ip_dst, puerto=dport, proto=proto)

def _dpi_tcp(payload, perfil, ip_src, ip_dst, dport, proto):
    """Inspección profunda de payload TCP."""
    if RE_SQLI.search(payload):
        alerta(ip_src, "sqli_attempt",
               f"SQL Injection en puerto {dport}: {payload[:60].decode('utf-8','replace')}",
               "CRITICAL", ip_dst=ip_dst, puerto=dport, proto=proto)
    if RE_XSS.search(payload):
        alerta(ip_src, "xss_attempt",
               f"XSS en puerto {dport}",
               "ERROR", ip_dst=ip_dst, puerto=dport, proto=proto)
    if RE_LFI.search(payload):
        alerta(ip_src, "lfi_rfi",
               f"LFI/RFI/Path Traversal en puerto {dport}",
               "CRITICAL", ip_dst=ip_dst, puerto=dport, proto=proto)
    if RE_SHELLCODE.search(payload):
        alerta(ip_src, "shellcode_tcp",
               f"Shellcode/NOP-sled en puerto {dport}",
               "CRITICAL", ip_dst=ip_dst, puerto=dport, proto=proto)
    if RE_CMDINJ.search(payload):
        alerta(ip_src, "cmd_injection",
               f"Command injection en puerto {dport}: {payload[:60].decode('utf-8','replace')}",
               "CRITICAL", ip_dst=ip_dst, puerto=dport, proto=proto)
    if RE_REVSHELL.search(payload):
        alerta(ip_src, "reverse_shell",
               f"Reverse shell en puerto {dport}",
               "CRITICAL", ip_dst=ip_dst, puerto=dport, proto=proto)
    if dport not in PUERTOS_HTTPS and RE_CREDS.search(payload):
        alerta(ip_src, "cleartext_credentials",
               f"Credenciales en claro en puerto {dport}",
               "ERROR", ip_dst=ip_dst, puerto=dport, proto=proto)
    if RE_PTOOL.search(payload):
        m = RE_PTOOL.search(payload)
        alerta(ip_src, "pentest_tool_detected",
               f"Herramienta de ataque: {m.group(0).decode('utf-8','replace')} puerto {dport}",
               "ERROR", ip_dst=ip_dst, puerto=dport, proto=proto)
    if payload.startswith(b"POST") and len(payload) > 50_000:
        perfil.large_upload += 1
        if perfil.large_upload > UMBRALES["large_upload"]:
            alerta(ip_src, "http_large_upload",
                   f"Upload HTTP masivo ({len(payload):,}B) → posible exfiltración",
                   "WARNING", ip_dst=ip_dst, puerto=dport, proto=proto)

# ══════════════════════════════════════════════════════════════════════════════
#  UDP
# ══════════════════════════════════════════════════════════════════════════════

def _analizar_udp(pkt, perfil: PerfilIP, ip_src: str, ip_dst: str, is_ipv6=False):
    udp   = pkt[UDP]
    dport = udp.dport
    proto = "UDPv6" if is_ipv6 else "UDP"

    perfil.conn     += 1
    perfil.udp_pkts += 1
    perfil.win_puertos.add(dport)

    if perfil.udp_pkts > UMBRALES["udp_flood"]:
        alerta(ip_src, "udp_flood",
               f"UDP Flood ({perfil.udp_pkts} pkts en {VENTANA_TIEMPO}s)",
               "CRITICAL", ip_dst=ip_dst, proto=proto)

    if len(perfil.win_puertos) > UMBRALES["port_scan"]:
        alerta(ip_src, "udp_port_scan",
               f"UDP Port Scan ({len(perfil.win_puertos)} puertos únicos)",
               "ERROR", ip_dst=ip_dst, proto=proto)

    if dport == 53:
        stats["proto"]["DNS"] += 1
        _analizar_dns(pkt, perfil, ip_src, ip_dst)
    elif dport == 67:
        stats["proto"]["DHCP"] += 1
        _analizar_dhcp(pkt, perfil, ip_src, ip_dst)
    elif dport == 123:
        stats["proto"]["NTP"] += 1
        _analizar_ntp(pkt, perfil, ip_src, ip_dst)
    elif dport in (161, 162):
        stats["proto"]["SNMP"] += 1
        _analizar_snmp(pkt, perfil, ip_src, ip_dst, dport)
    elif dport == 1900:
        stats["proto"]["SSDP"] += 1
        perfil.ssdp += 1
        if perfil.ssdp > UMBRALES["ssdp_flood"]:
            alerta(ip_src, "ssdp_flood",
                   f"SSDP/UPnP Flood ({perfil.ssdp}) → DDoS amplification",
                   "ERROR", ip_dst=ip_dst, puerto=1900, proto=proto)
    elif dport == 11211:
        alerta(ip_src, "memcached_amplification",
               "Memcached UDP → DDoS amplification (x50000)",
               "CRITICAL", ip_dst=ip_dst, puerto=11211, proto=proto)
    elif dport == 19:
        alerta(ip_src, "chargen_amplification",
               "CHARGEN → DDoS amplification",
               "ERROR", ip_dst=ip_dst, puerto=19, proto=proto)
    elif dport == 69:
        alerta(ip_src, "tftp_access",
               "TFTP (sin autenticación) → exfiltración/firmware",
               "WARNING", ip_dst=ip_dst, puerto=69, proto=proto)
    elif dport == 1883:
        alerta(ip_src, "mqtt_insecure",
               "MQTT sin TLS → compromiso IoT",
               "WARNING", ip_dst=ip_dst, puerto=1883, proto=proto)
    elif dport in PUERTOS_SCADA:
        alerta(ip_src, "scada_udp_access",
               f"ICS/SCADA UDP: {nombre_puerto(dport)} ({dport})",
               "CRITICAL", ip_dst=ip_dst, puerto=dport, proto=proto)

# ══════════════════════════════════════════════════════════════════════════════
#  DNS
# ══════════════════════════════════════════════════════════════════════════════

def _analizar_dns(pkt, perfil: PerfilIP, ip_src: str, ip_dst: str):
    if not pkt.haslayer(DNS):
        return
    dns = pkt[DNS]
    perfil.dns += 1

    if perfil.dns > UMBRALES["dns_flood"]:
        alerta(ip_src, "dns_flood",
               f"DNS Flood ({perfil.dns} queries en {VENTANA_TIEMPO}s)",
               "WARNING", ip_dst=ip_dst, proto="DNS")

    if dns.qr == 0 and pkt.haslayer(DNSQR):
        try:
            qname = dns[DNSQR].qname.decode(errors="replace").rstrip(".")
        except Exception:
            return
        qtype_n = dns[DNSQR].qtype
        log.debug(f"[DNS] {ip_src} qtype={qtype_n} {qname}")

        if len(qname) > 80:
            perfil.dns_tunnel += 1
            alerta(ip_src, "dns_tunnel",
                   f"DNS Tunneling: query {len(qname)} chars → {qname[:50]}…",
                   "ERROR", ip_dst=ip_dst, proto="DNS")

        partes = qname.split(".")
        if len(partes) > 5:
            alerta(ip_src, "dns_dga",
                   f"DGA: {len(partes)} niveles de subdominio → {qname[:50]}",
                   "WARNING", ip_dst=ip_dst, proto="DNS")

        sub = partes[0] if partes else ""
        if len(sub) > 10 and _entropia(sub) > 3.8:
            alerta(ip_src, "dns_high_entropy",
                   f"Alta entropía en subdominio '{sub[:20]}' → C2/DGA beaconing",
                   "WARNING", ip_dst=ip_dst, proto="DNS")

        if qtype_n == 255:
            alerta(ip_src, "dns_any_query",
                   f"DNS ANY ({qname}) → amplification",
                   "WARNING", ip_dst=ip_dst, proto="DNS")
        if qtype_n == 252:
            alerta(ip_src, "dns_zone_transfer",
                   f"Zone Transfer AXFR para {qname}",
                   "CRITICAL", ip_dst=ip_dst, proto="DNS")

# ══════════════════════════════════════════════════════════════════════════════
#  DHCP
# ══════════════════════════════════════════════════════════════════════════════

def _analizar_dhcp(pkt, perfil: PerfilIP, ip_src: str, ip_dst: str):
    if not pkt.haslayer(DHCP):
        return
    for opt in pkt[DHCP].options:
        if not isinstance(opt, tuple) or opt[0] != "message-type":
            continue
        msg = opt[1]
        if msg == 1:
            perfil.dhcp_disc += 1
            if perfil.dhcp_disc > UMBRALES["dhcp_discover"]:
                alerta(ip_src, "dhcp_starvation",
                       f"DHCP Starvation ({perfil.dhcp_disc} DISCOVERs) → agotamiento pool",
                       "CRITICAL", ip_dst=ip_dst, proto="DHCP")
        elif msg == 2:
            alerta(ip_src, "dhcp_rogue_server",
                   "DHCP OFFER inesperado → servidor DHCP rouge/MITM",
                   "CRITICAL", ip_dst=ip_dst, proto="DHCP")

# ══════════════════════════════════════════════════════════════════════════════
#  NTP / SNMP
# ══════════════════════════════════════════════════════════════════════════════

def _analizar_ntp(pkt, perfil: PerfilIP, ip_src: str, ip_dst: str):
    perfil.ntp += 1
    if perfil.ntp > UMBRALES["ntp_flood"]:
        alerta(ip_src, "ntp_flood",
               f"NTP Flood ({perfil.ntp} pkts)",
               "ERROR", ip_dst=ip_dst, proto="NTP")
    if pkt.haslayer(Raw) and len(pkt[Raw].load) > 200:
        alerta(ip_src, "ntp_amplification",
               f"NTP Amplification ({len(pkt[Raw].load)}B) → monlist DDoS",
               "CRITICAL", ip_dst=ip_dst, puerto=123, proto="NTP")

def _analizar_snmp(pkt, perfil: PerfilIP, ip_src: str, ip_dst: str, dport: int):
    perfil.snmp += 1
    if perfil.snmp > UMBRALES["snmp_queries"]:
        alerta(ip_src, "snmp_enumeration",
               f"SNMP Enumeration ({perfil.snmp} queries)",
               "WARNING", ip_dst=ip_dst, puerto=dport, proto="SNMP")
    if pkt.haslayer(Raw):
        pl = pkt[Raw].load
        if len(pl) > 500:
            alerta(ip_src, "snmp_amplification",
                   "SNMP Bulk → amplification DDoS",
                   "ERROR", ip_dst=ip_dst, puerto=dport, proto="SNMP")
        if b"public" in pl:
            alerta(ip_src, "snmp_community_public",
                   "Community string 'public' en SNMP → configuración insegura",
                   "INFO", ip_dst=ip_dst, puerto=dport, proto="SNMP")

# ══════════════════════════════════════════════════════════════════════════════
#  REPORTE FINAL
# ══════════════════════════════════════════════════════════════════════════════

def _reporte_final():
    # Restaurar cursor y limpiar
    sys.stdout.write("\033[?25h\033[H\033[J")
    sys.stdout.flush()

    uptime = int(time.time() - stats["inicio"])
    sep    = "═" * 72
    print(f"\n{sep}")
    print("  AIDS v4.0 — Reporte Final")
    print(sep)
    print(f"  Uptime              : {uptime//3600:02d}h {(uptime%3600)//60:02d}m {uptime%60:02d}s")
    print(f"  Paquetes            : {stats['paquetes_totales']:,}")
    print(f"  Bytes               : {stats['bytes_totales']:,}")
    print(f"  IPs únicas          : {len(stats['ips_unicas'])}")
    print(f"  Alertas             : {stats['alertas_totales']}")
    print(f"  Bloqueos aplicados  : {stats['acciones']['block']}")
    print(f"  Cuarentenas         : {stats['acciones']['quarantine']}")
    print()

    if historial_alertas:
        ip_c   = Counter(a["ip_src"] for a in historial_alertas)
        tipo_c = Counter(a["tipo"]   for a in historial_alertas)
        print("  Top IPs más activas:")
        for ip, cnt in ip_c.most_common(10):
            print(f"    {ip:<22} {cnt:>5} alertas")
        print()
        print("  Top tipos de alerta:")
        for tipo, cnt in tipo_c.most_common(15):
            print(f"    {tipo:<38} {cnt:>5}")
        print()

    if ARGS.json:
        print(f"  JSONL: {JSON_FILE}")
    print(f"  Log  : {LOG_FILE}")
    print(sep)

# ══════════════════════════════════════════════════════════════════════════════
#  SEÑALES
# ══════════════════════════════════════════════════════════════════════════════

def _handler_signal(sig, frame):
    fw.limpiar_todo()
    _reporte_final()
    sys.exit(0)

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

BANNER = r"""
  ______   ______  _______    ______  
 /      \ /      |/       \  /      \  
/$$$$$$  |$$$$$$/ $$$$$$$  |/$$$$$$  |  Autonomous Intrusion Detection System                
$$ |__$$ |  $$ |  $$ |  $$ |$$ \__$$/   v4.0 · Auto-Learning · Auto-Block · Quarantine
$$    $$ |  $$ |  $$ |  $$ |$$      \ 
$$$$$$$$ |  $$ |  $$ |  $$ | $$$$$$  |
$$ |  $$ | _$$ |_ $$ |__$$ |/  \__$$ |
$$ |  $$ |/ $$   |$$    $$/ $$    $$/ 
$$/   $$/ $$$$$$/ $$$$$$$/   $$$$$$/  
"""

def main():
    global log, fw

    if os.name != "nt" and os.geteuid() != 0:
        print("[FATAL] Requiere root: sudo python3 ids_avanzado.py")
        sys.exit(1)

    log = _init_log(LOG_FILE, ARGS.debug)
    fw  = Firewall(enabled=not ARGS.no_block)

    signal.signal(signal.SIGINT,  _handler_signal)
    signal.signal(signal.SIGTERM, _handler_signal)

    # Hilo de auto-desbloqueo
    t_gc = threading.Thread(target=fw.gc_auto_desbloqueo, daemon=True, name="AIDS-GC")
    t_gc.start()

    # Limpiar pantalla e iniciar dashboard
    sys.stdout.write("\033[2J\033[H")
    sys.stdout.flush()
    print(BANNER)
    print(f"  Host    : {socket.gethostname()}")
    print(f"  Interfaz: {ARGS.iface or 'todas'}")
    print(f"  Bloqueo : {'DESACTIVADO (--no-block)' if ARGS.no_block else f'ACTIVO  score>={BLOCK_SCORE}=bloqueo  score>={QUARANTINE_SCORE}=cuarentena'}")
    print(f"  Auto-desbloqueo en {BLOCK_TIME}s  |  Baseline: {BASELINE_WINDOW}s de aprendizaje por IP")
    print(f"  Log: {LOG_FILE}" + (f"  JSONL: {JSON_FILE}" if ARGS.json else ""))
    print()
    time.sleep(2)

    # Hilo dashboard
    t_dash = threading.Thread(target=_hilo_dashboard, daemon=True, name="AIDS-Dashboard")
    t_dash.start()

    log.info(f"AIDS v4.0 iniciado | iface={ARGS.iface} block={'no' if ARGS.no_block else 'si'}")

    sniff(
        iface=ARGS.iface,
        prn=analizar,
        store=0,
        filter="ip or ip6 or arp",
    )

if __name__ == "__main__":
    main()
