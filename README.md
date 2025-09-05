# Protect Edge Host on Debian using NFtables + CrowdSec

En esta guia aprenderemos a bastionar un equipo con acceso desde internet para usarlo de frontera(VPN) y estar algo mas protegido de las amenazas de internet (no existe sistema 100% seguro).

Esta guia te proporciona una configuracion avanzada de nftables con un conjunto dinamico que se integra con Crowdsec. 
            
Con esta solucion, tu sistema Debian 13 estaraa mas protegido contra escaneos de nmap y accesos SSH no autorizados,

Ademas de contar con una capa colaborativa de seguridad que bloquea automaticamente las IPs con mala reputacion.

 
---

![Portada de Firewall](Firewall_Linux_Portada.png)

---

## :book: Indice

* [ :cop: Terminos de uso](README.md)
* [:atom: Caracteristicas](#atom-caracteristicas)
* [:white_check_mark: Requisitos](#white_check_mark-requisitos)
* [:gear: 1 Instalar el software necesario](#gear-1-instalar-el-software-necesario)
* [:lock: 2 Configurar Nftables](#lock-2-configurar-nftables)
    * [2.1 Crear el archivo de nftables](#21-crear-el-archivo-de-nftables)
* [:wrench: 3 Configuracion de Crowdsec](#wrench-3-configuracion-de-crowdsec)
    * [3.1 Escenarios de CrowdSec](#31-escenarios-de-crowdsec)
    * [3.2 Integracion con nftables](#32-integracion-con-nftables)
* [:ballot_box_with_check: 4 Verificacion y Monitorizacion](#ballot_box_with_check-4-verificacion-y-monitorizacion)
    * [4.1 Reglas activas](#41-reglas-activas)
    * [4.2 Comprobar estado de Crowdsec](#42-comprobar-estado-de-crowdsec)
    * [4.3 Administrar decisiones](#43-administrar-decisiones)
        * [4.3.1 Agregar decisiones](#431-agregar-decisiones)
        * [4.3.2 Eliminar decisiones](#432-eliminar-decisiones)
        * [4.3.3 Listar decisiones](#433-listar-decisiones)
    * [4.4 Monitorear metricas](#44-monitorear-metricas)
* [:rotating_light: 5 Consejos](#rotating_light-5-consejos)

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

Actualizar la lista de paquetes disponibles:
```bash
sudo apt update
```

Instalamos el software:

```bash
sudo apt install nftables crowdsec crowdsec-firewall-bouncer-nftables
```


# :lock: 2 Configurar Nftables


El sistema de firewall nftables se configura creando un archivo que organiza las reglas en una jerarquia clara. 

En la cima estan las tablas, que actuan como contenedores logicos para las reglas, como la tabla filter para el filtrado de paquetes.

Dentro de cada tabla se definen cadenas, que son listas ordenadas de reglas. 

Las cadenas base son puntos de entrada para el trafico de red, vinculadas a puntos especificos del kernel (hooks) como input (para el trafico entrante), output (para el saliente) y forward (para el trafico que atraviesa el sistema). 

Tambien puedes crear cadenas regulares personalizadas para organizar las reglas de forma mas modular y llamarlas desde una cadena base. 

Finalmente, las reglas son las instrucciones que se ejecutan sobre un paquete que coincide con ciertas condiciones, con acciones como accept, drop o jump (saltar a otra cadena).

## 2.1 Crear el archivo de nftables

Este es un conjunto de reglas recopilado para intentar aplicar la seguridad posible sin restar rendimiento, siempre puede ser mejorable y mas restrictivo, esto solo es un grueso de trabajo ya hecho por mi.

 :clipboard: Explicacion de las principales reglas:

* flush ruleset: Limpia cualquier regla previa para evitar conflictos.
* table intet filter: Tabla pricipal que contendra toda la escructura y las cadenas mas con los conjuntos de nuestro nftables
* blocklist-ipv4: Define un conjunto dinamico de IPs version 4 que se bloquearan automaticamente durante el tiempo que estime CrowdSec.
* blocklist-ipv6: Define un conjunto dinamico de IPs version 6 que se bloquearan automaticamente durante el tiempo que estime CrowdSec.
* chain input: Cadena  que contendra todas las reglas de entrada a nuestra maquina.
* ct state established,related accept: Permite trafico de conexiones ya establecidas o relacionadas.
* iifname "lo" accept: Se permite el trafico de la interfaz loopback.
* ICMP: Se permite el ping (echo-request y echo-reply).
* SSH con limitacion: Solo se aceptan hasta 10 nuevas conexiones por minuto al puerto 22, ayudando a mitigar ataques de fuerza bruta.
* ip saddr @crowdsec-blacklist-ipv4 drop: Bloquea el trafico proveniente de IPs version 4 presentes en la lista dinamica de CrowdSec.
* ip saddr @crowdsec-blacklist-ipv6 drop: Bloquea el trafico proveniente de IPs version 6 presentes en la lista dinamica de CrowdSec.
* Bloqueo de escaneos nmap: Se aplican reglas para descartar paquetes con combinaciones de flags consideradas anomalas (caracteristicas de ciertos escaneos).
* chain forward: Esta cadena contrendra las reglas de reenvio de trafico en la maquina, por defecto todo deshabilitado.
* chain output: Esta cadena contrendra las reglas de salida de trafico en la maquina, por defecto todo el trafico saliente habilitado.


```bash
nano /etc/nftables.conf
```
:warning: Recuerda reemplazar las direcciones de red, puertos y comentar lo que no necesites para tu entorno.

```bash
flush ruleset

table inet filter {

        # Conjunto dinamico de IPs bloqueadas de CrowdSec (IPv4)
        set crowdsec-blacklist-ipv4 {
        type ipv4_addr
        flags dynamic, timeout
        }

        # Conjunto dinamico de IPs bloqueadas de CrowdSec (IPv6)
        set crowdsec-blacklist-ipv6 {
        type ipv6_addr
        flags dynamic, timeout
        }

        chain input {
                type filter hook input priority 0; policy drop;

        # Permitir conexiones ya establecidas o relacionadas
                ct state established,related accept

        # Permitir trafico en la interfaz local (loopback)
                iifname "lo" accept

       # Bloquear IPs que esten en la blacklist (actualizada por Crowdsec)
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

        # Combinaciones invalidas de flags (SYN con FIN)
                tcp flags & (syn|fin) == syn|fin drop comment "SYN+FIN"

        # Combinaciones invalidas de flags (SYN con RST)
                tcp flags & (syn|rst) == syn|rst drop comment "SYN+RST"

        # Escaneo ACK+FIN o FIN+ACK
                tcp flags & (ack|fin) == ack|fin drop comment "ACK|FIN + FYN|ACK scan"

        # Escaneo Maimon: FIN activo con URG/PSH inactivos
                tcp flags & (fin|psh|urg) == fin drop

        # Proteccion contra paquetes invalidos (ej. sin handshake TCP)
                ct state invalid counter drop

        # Proteccion contra fragmentacion sospechosa
                ip frag-off & 0x1fff != 0 counter drop

        # Bloquear flags reservados (ECN/CWR activos sin negociacion previa)
                tcp flags & (ecn|cwr) != 0x0 drop comment "Flags reservados activos (RFC 3540)"

        # Escaneo ACK: Usado para detectar reglas de firewall.
                tcp flags ack tcp flags & (syn|fin|rst|urg|psh) == 0 drop comment "Bloquear escaneos ACK"

        # Anti-fingerprinting
        #       tcp option timestamp exists drop comment "Bloquear timestamp (OS detection)"
                tcp option sack-perm exists drop comment "Bloquear SACK (manipulacion de paquetes)"
                tcp option md5sig exists drop comment "Evitar firmas MD5 (rare en escaneos)"
                tcp option window exists drop comment "Bloquear opcion Window Scale"
                tcp option mss exists drop comment "Bloquear MSS para evitar fingerprinting"

        #Bloquear escaneos Window basados en tamaño de ventana TCP
                tcp flags ack tcp window <= 1024 drop comment "Bloquear escaneos Window"

        # Bloquear paquetes con puerto fuente 0 (anomalo en escaneos o intentos de evasion)
                tcp sport 0 drop comment "Bloquear paquetes con puerto fuente 0"

        # Bloquear paquetes con puerto destino 0 (anomalo en escaneos o intentos de evasion)
                tcp dport 0 drop comment "Bloquear paquetes con puerto destino 0"

        #Proteccion extendida TCP
                tcp option fastopen exists drop comment "Bloquear TCP Fast Open (RFC 7413)"

        # Limite global de nuevas conexiones (Opcional)
        # ct state new limit rate 30/second counter accept

        # Logging de paquetes bloqueados (opcional)
                counter log prefix " [(PAQUETE BLOQUEADO)]: " drop

        }

        chain forward {
                type filter hook forward priority 0; policy drop;

         # Permitir trafico entre WireGuard y la red local
                iifname "wg0" oifname "enP3p49s0" accept  # Cambia "eth0" por tu interfaz LAN
                iifname "enP3p49s0" oifname "wg0" ct state established,related accept

        # Permitir trafico especifico desde 10.10.10.1 hacia 192.168.1.0/24
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


   :warning: (IMPORTANTE) Una vez guardado el archivo, revisa la configuracion ejecutando:

   ```bash
   sudo nft -f /etc/nftables.conf
   ```

:white_check_mark: Si el comando no duelve nada el fichero esta correcto.

---
# :wrench: 3 Configuracion de Crowdsec
Crowdsec es una herramienta empresarial con modelo gratutito colaborativo.

Esta posee una base de datos de amenazas centralizada, CrowdSec analiza logs en busca de comportamientos maliciosos y genera alertas que se envian a esta base de datos centralizada (por ejemplo, intentos de acceso no autorizado) cuando la base de datos recibe la alerta de varios hosts añade esa ip o rango a la blacklist de la base de datos.

Esto nos permite quitarnos un grueso malicioso de IPs o de rangos sospechosos que estan recorriendo la red constantemente.

## 3.1 Escenarios de CrowdSec
Los "escenarios" son las reglas de deteccion que utiliza el agente, mientras que el "bouncer" es el componente que se encarga de la accion de bloqueo. 

Por lo tanto son dos partes clave de un sistema de seguridad que trabajan juntas.

Esto permite que solo busque y analice lo que nos interesa, haciendolo mas eficiente y modular.

En resumen:
CrowdSec Agent (LSO): Detecta ataques basandose en escenarios.

Bouncer: Aplica las medidas de mitigacion (bloqueos) basandose en las decisiones del agente.

Para nuestro caso como usamos Debian con SSH y VPN en la maquina instalamos:

 ```bash
sudo cscli collections install crowdsecurity/linux
sudo cscli collections install crowdsecurity/sshd
sudo cscli collections install crowdsecurity/wireguard
```
:book: Tienes todas las colecciones disponibles con:
 ```bash
sudo cscli collections list -a
 ```

:white_check_mark: Si nos inidica "Nothing to install or remove" ya estaran instaladas.

Comprobamos los escenarios con:

 ```bash
cscli scenarios list
```
---
En resumen:
CrowdSec Agent (LSO): Detecta ataques basandose en escenarios.

Bouncer: Aplica las medidas de mitigacion (bloqueos) basandose en las decisiones del agente.


## 3.2 Integracion con nftables
El bouncer leera las decisiones generadas por Crowdsec (por ejemplo, detectar intentos fallidos de SSH o actividad sospechosa) y actualizara automaticamente
el conjunto blocklist definido en tu archivo de nftables. 

De esta forma, las IPs maliciosas quedaran bloqueadas durante el tiempo configurado por CrowdSec.
        
Si deseas que CrowdSec actualice las listas en tu fichero de reglas personalizadas, debes modificar la configuracion del bouncer para que apunte a la misma tabla y cadena
donde se encuentran tus sets en el fichero /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml

En el apartado deny_log lo cambiaremos de "false" a "true" y mas abajo descomentamos deny_log_prefix y lo personalizamos con " [(CrowdSec BLOCK)]: "

En el apartado de blacklists es importante especificar los set de blacklists creadas para CrowdSec en nuestro /etc/nftables.conf (crowdsec-blacklist-ipv4 y crowdsec-blacklist-ipv6)
        
En el apartado  ## nftables del fichero debemos modificar los valores "table" y "chain" con "filter" e "input" tal y como hemos puesto nuestro fichero /etc/nftables.conf tanto para el apartado IPv4 como IPv6.

Editamos:
 ```bash
sudo   nano /etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml
 ```

 Deberia quedar algo como esto:
  ```yaml
log_mode: file
log_dir: /var/log/
log_level: info
insecure_skip_verify: false
disable_ipv6: false
deny_action: DROP
deny_log: true
supported_decisions_types:
  - ban
#to change log prefix
deny_log_prefix: " [(CrowdSec BLOCK)]: "
#to change the blacklists name
blacklists_ipv4: crowdsec-blacklist-ipv4
blacklists_ipv6: crowdsec-blacklist-ipv6
#type of ipset to use
ipset_type: nethash
#if present, insert rule in those chains
iptables_chains:
  - INPUT
#  - FORWARD
#  - DOCKER-USER

## nftables
nftables:
  ipv4:
    enabled: true
    set-only: false
    table: filter
    chain: input
    priority: -10
  ipv6:
    enabled: true
    set-only: false
    table: filter
    chain: input
    priority: -10

nftables_hooks:
  - input
  - forward

 ```
 ---

 Para asegurarte de que todos los cambios se apliquen, reinicia los servicios de Crowdsec y del bouncer:

  ```bash
sudo systemctl restart crowdsec
sudo systemctl restart crowdsec-firewall-bouncer-nftables
```

# :ballot_box_with_check: 4 Verificacion y Monitorizacion

## 4.1 Reglas activas
Para comprobar que las reglas estan activas, utiliza:
```bash
sudo nft list ruleset
```
## 4.2 Comprobar estado de Crowdsec
Revisa los logs de Crowdsec para ver la actividad y decisiones:
```bash
sudo journalctl -u crowdsec
```
## 4.3 Administrar decisiones
Las decisiones son las reglas que bloquaran o no el trafico desde las direcciones espeficificadas, para administrarlas tenemos las siguientes utilidades.

### 4.3.1 Agregar decisiones
Individual: (No recomendedado, muchas entradas hacen el programa menos eficiente)
```bash
sudo cscli decisions add --ip 192.168.1.1 --duration 87600h --reason "web bruteforce"
```
Rango: (Ejemplo para la red 162.142.125.0/24)
```bash 
sudo cscli decisions add --ip cscli decisions add --range 162.142.125.0/24 --duration 87600h --reason "Ataques SSH de Cersys" 109.205.213.99 --duration 0 --reason "Ataque SSH"
```

### 4.3.2 Eliminar decisiones
Individual: (Ejemplo de Borrado de la decision con IP address 162.142.125.50)
```bash
sudo cscli decisions delete --ip 162.142.125.50
```
Rango: (Borrado de decisiones con IP rango 162.142.125.0/24)
```bash
sudo cscli decisions delete --ip 162.142.125.0/24
```

### 4.3.3 Listar decisiones
```bash
cscli decisions list
```

## 4.4 Monitorear metricas
Crowdsec recopila estadisticas del trafico bloqueado por nuestra maquina.

Esto nos permite ver que desiones estan rechazando ataques y cuanta cantidad.

Para ver todas las metricas:

```bash
cscli metrics
```

Para comparar los paquetes bloqueados por nosotros vs CrowdSec:
```bash
cscli metrics  show bouncers
```

El bouncer actualiza dinamicamente la blacklistdel nftables.
Puedes revisar esta lista con:

```bash
 sudo nft list ruleset
```

Tambien puedes revisar los sets especificos que CrowdSec crea con: 

```bash 
 sudo nft list set inet filter "nombre del set"
```

Monitorear las decisiones tomadas: 

```bash
sudo cscli decisions list
```

Monitorear las alertas tomadas debido a decisiones:

```bash 
 sudo cscli alerts list
```

# :rotating_light: 5 Consejos

 Revisa periodicamente los logs y las decisiones para afinar la configuracion de seguridad segun el comportamiento real de tu red.

Los paquetes bloqueados apareceran como 2025-03-23T01:20:25.832745+01:00 Hostname kernel: [40387.495652]  [(PAQUETE BLOQUEADO)]: +  "las direcciones origen - destino"

```bash 
sudo cat /var/log/kern.log
sudo cat /var/log/syslog
```    
      
Las conexiones que no consiga bloquear el firewall aparecen en:

```bash 
sudo cat /var/log/auth.log   
```
      
Comprobar que CrowdSec envia metricas y no tiene errores:

```bash 
sudo cat /var/log/crowdsec.log
```       

Comprobar que el Bouncer Firewall de CrowdSec para nftables actualiza las decisiones de la base de datos de CrowdSec y no tiene errores:

```bash 
sudo cat /var/log/crowdsec-firewall-bouncer.log
```

Implementa y ajusta estas configuraciones segun las caracteristicas especificas de tu red para mantener una defensa proactiva y adaptativa.