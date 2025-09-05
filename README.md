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

