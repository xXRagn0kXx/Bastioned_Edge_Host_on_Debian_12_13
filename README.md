# Protect Edge Host on Debian using NFtables + CrowdSec

En esta guia aprenderemos a bastionar un equipo con acceso desde internet para usarlo de frontera(VPN) y estar algo mas protegido de las amenazas de internet (no existe sistema 100% seguro).

---

![Portada de Firewall](Firewall_Linux_Portada.png)

---

## :atom: Caracteristicas

* Compatible con cualquier arquitectura de debian 12 y 13.
* El firewall del sistema sera nftables por su granularidad y eficiencia
* Como apoyo al firewall usaremos la herrmienta CrowdSec basada en reputacion
* Esto permite usar el host como VPN  de forma mas confiable

## :white_check_mark: Requisitos

* Conocimiento medio o avanzado del sistema
* Conocimiento medio o avanzado de reglas
* Un servidor o maquina con Debian 12 o 13 con conexion a internet
* Permisos de sudo o usuario root para cambios

---

# :gear: 1 Instalar el software necesario

CrowdSec ya esta en los repositorios de Debian, pero debido a que es un elemento de seguridad
lo conveniente es agregar el repositorio de crowdsec para tener la ultima version actualizada siempre.

Si se prefiere usar el repositorio de Debian (catalogado como lo mas estable) omitir este paso:

```bash
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash
```

Una vez agregado (o no) procedemos a la instalacion

Actualizar la lista de paquetes disponibles
```bash
sudo apt update
```

Instalamos el software

```bash
sudo apt install nftables crowdsec crowdsec-firewall-bouncer-nftables
```


# :lock: 2 Configurar Nftables


El sistema de firewall nftables se configura a creando un archivo que organiza las reglas en una jerarquía clara. 

En la cima están las tablas, que actúan como contenedores lógicos para las reglas, como la tabla filter para el filtrado de paquetes. Dentro de cada tabla se definen cadenas, que son listas ordenadas de reglas. 

Las cadenas base son puntos de entrada para el tráfico de red, vinculadas a puntos específicos del kernel (hooks) como input (para el tráfico entrante), output (para el saliente) y forward (para el tráfico que atraviesa el sistema). 

También puedes crear cadenas regulares personalizadas para organizar las reglas de forma más modular y llamarlas desde una cadena base. 

Finalmente, las reglas son las instrucciones que se ejecutan sobre un paquete que coincide con ciertas condiciones, con acciones como accept, drop o jump (saltar a otra cadena).

Creamos o editamos el archivo

```bash
nano /etc/nftables.conf
```
Este es un conjunto de reglas recopilado para intentar aplicar la seguridad posible sin restar rendimiento, siempre puede ser mejorable y mas restrictivo, esto solo es un grueso de trabajo ya hecho por mi.

:warning: Recuerda reemplazar las direcciones de red y puertos que necesites para tu entorno.

```bash
flush ruleset

table inet filter {

        # Conjunto dinámico de IPs bloqueadas de CrowdSec (IPv4)
        set crowdsec-blacklist-ipv4 {
        type ipv4_addr
        flags dynamic, timeout
        }

        # Conjunto dinámico de IPs bloqueadas de CrowdSec (IPv6)
        set crowdsec-blacklist-ipv6 {
        type ipv6_addr
        flags dynamic, timeout
        }

        chain input {
                type filter hook input priority 0; policy drop;

        # Permitir conexiones ya establecidas o relacionadas
                ct state established,related accept

        # Permitir tráfico en la interfaz local (loopback)
                iifname "lo" accept

       # Bloquear IPs que estén en la blacklist (actualizada por Crowdsec)
                ip saddr @crowdsec-blacklist-ipv4 drop
                ip6 saddr @crowdsec-blacklist-ipv6 drop

        # Permitir ICMP (ping) - solo echo-request y echo-reply
                ip protocol icmp icmp type { echo-request, echo-reply } accept

        # Permitir conexiones TCP (puerto 22) y limitar nuevas conexiones a 10 por minuto añadiendolas a un contador
        #       tcp dport 22 ct state new limit rate 10/minute counter accept

        # Permitir conexiones SSH (puerto 22) y limitar nuevas conexiones a 10 por minuto añadiendolas a un contador
                tcp dport 22 ct state new tcp flags syn limit rate 4/minute counter accept

        # WireGuard (protegido igual que SSH pero para UDP)
                udp dport 51820 ct state new limit rate 10/minute counter accept

        # Bloquear escaneos nmap comunes mediante combinaciones inusuales de flags TCP
        # Escaneo NULL: todos los flags desactivados (0x0)
                tcp flags & (fin|syn|rst|psh|ack|urg) == 0x0 drop comment "NULL scan"

        # Escaneo FIN: solo flag FIN activo
                tcp flags & (fin|syn) == fin drop comment "FIN scan"

        # Escaneo XMAS: FIN, PSH y URG activos
                tcp flags & (fin|psh|urg) == fin|psh|urg drop comment "XMAS scan"

        # Combinaciones inválidas de flags (SYN con FIN)
                tcp flags & (syn|fin) == syn|fin drop comment "SYN+FIN"

        # Combinaciones inválidas de flags (SYN con RST)
                tcp flags & (syn|rst) == syn|rst drop comment "SYN+RST"

        # Escaneo ACK+FIN o FIN+ACK
                tcp flags & (ack|fin) == ack|fin drop comment "ACK|FIN + FYN|ACK scan"

        # Escaneo Maimon: FIN activo con URG/PSH inactivos
                tcp flags & (fin|psh|urg) == fin drop

        # Protección contra paquetes inválidos (ej. sin handshake TCP)
                ct state invalid counter drop

        # Protección contra fragmentación sospechosa
                ip frag-off & 0x1fff != 0 counter drop

        # Bloquear flags reservados (ECN/CWR activos sin negociación previa)
                tcp flags & (ecn|cwr) != 0x0 drop comment "Flags reservados activos (RFC 3540)"

        # Escaneo ACK: Usado para detectar reglas de firewall.
                tcp flags ack tcp flags & (syn|fin|rst|urg|psh) == 0 drop comment "Bloquear escaneos ACK"

        # Anti-fingerprinting
        #       tcp option timestamp exists drop comment "Bloquear timestamp (OS detection)"
                tcp option sack-perm exists drop comment "Bloquear SACK (manipulación de paquetes)"
                tcp option md5sig exists drop comment "Evitar firmas MD5 (rare en escaneos)"
                tcp option window exists drop comment "Bloquear opción Window Scale"
                tcp option mss exists drop comment "Bloquear MSS para evitar fingerprinting"

        #Bloquear escaneos Window basados en tamaño de ventana TCP
                tcp flags ack tcp window <= 1024 drop comment "Bloquear escaneos Window"

        # Bloquear paquetes con puerto fuente 0 (anómalo en escaneos o intentos de evasión)
                tcp sport 0 drop comment "Bloquear paquetes con puerto fuente 0"

        # Bloquear paquetes con puerto destino 0 (anómalo en escaneos o intentos de evasión)
                tcp dport 0 drop comment "Bloquear paquetes con puerto destino 0"

        #Protección extendida TCP
                tcp option fastopen exists drop comment "Bloquear TCP Fast Open (RFC 7413)"

        # Límite global de nuevas conexiones (Opcional)
        # ct state new limit rate 30/second counter accept

        # Logging de paquetes bloqueados (opcional)
                counter log prefix " [(PAQUETE BLOQUEADO)]: " drop

        }

        chain forward {
                type filter hook forward priority 0; policy drop;

         # Permitir tráfico entre WireGuard y la red local
                iifname "wg0" oifname "enP3p49s0" accept  # Cambia "eth0" por tu interfaz LAN
                iifname "enP3p49s0" oifname "wg0" ct state established,related accept

        # Permitir tráfico específico desde 10.10.10.1 hacia 192.168.1.0/24
                ip saddr 10.10.10.0/24 ip daddr 192.168.1.0/24 accept

        }

        chain output {
                type filter hook output priority 0; policy accept;
        }

        chain nat {
        type nat hook postrouting priority 100; policy accept;
        ip saddr 10.10.10.0/24 oifname "enP3p49s0" masquerade
        }
}
```