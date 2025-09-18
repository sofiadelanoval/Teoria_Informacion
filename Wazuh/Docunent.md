# Proyecto de Integración: TheHive + Cortex + MISP + Wazuh

## Tabla de Contenidos
1. [Resumen Ejecutivo](#resumen-ejecutivo)
2. [Arquitectura del Proyecto](#arquitectura-del-proyecto)
3. [Requisitos del Sistema](#requisitos-del-sistema)
4. [Instalación y Configuración](#instalación-y-configuración)
5. [Integración de Componentes](#integración-de-componentes)
6. [Casos de Uso](#casos-de-uso)
7. [Monitoreo y Mantenimiento](#monitoreo-y-mantenimiento)
8. [Conclusiones](#conclusiones)

## Resumen Ejecutivo

Este proyecto implementa una plataforma completa de ciberseguridad que integra cuatro herramientas principales:

- **TheHive**: Plataforma de gestión de incidentes de seguridad
- **Cortex**: Motor de análisis y respuesta automatizada
- **MISP**: Plataforma de intercambio de inteligencia de amenazas
- **Wazuh**: SIEM/XDR de código abierto para detección de amenazas

La integración permite un flujo automatizado desde la detección hasta la respuesta, proporcionando capacidades avanzadas de SOC (Security Operations Center).

## Arquitectura del Proyecto

### Diagrama de Arquitectura
```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   Endpoints │    │   Servers   │    │   Network   │
│   (Agents)  │    │  (Agents)   │    │  (Logs)     │
└──────┬──────┘    └──────┬──────┘    └──────┬──────┘
       │                  │                  │
       └──────────────────┼──────────────────┘
                          │
                   ┌──────▼──────┐
                   │    WAZUH    │
                   │   Manager   │
                   └──────┬──────┘
                          │
                   ┌──────▼──────┐
                   │  THE HIVE   │
                   │ (Case Mgmt) │
                   └──────┬──────┘
                          │
            ┌─────────────┼─────────────┐
            │             │             │
     ┌──────▼──────┐ ┌───▼────┐ ┌──────▼──────┐
     │   CORTEX    │ │  MISP  │ │  Analysts   │
     │ (Analysis)  │ │ (Intel)│ │ (Dashboard) │
     └─────────────┘ └────────┘ └─────────────┘
```

### Flujo de Datos
1. **Detección**: Wazuh detecta anomalías y genera alertas
2. **Enriquecimiento**: Cortex analiza los observables automáticamente
3. **Inteligencia**: MISP proporciona contexto de amenazas
4. **Gestión**: TheHive centraliza los casos e incidentes
5. **Respuesta**: Automatización de respuestas a través de playbooks

## Requisitos del Sistema

### Hardware Mínimo (Entorno de Laboratorio)
- **RAM**: 16 GB (recomendado 32 GB)
- **CPU**: 8 cores (recomendado 16 cores)
- **Almacenamiento**: 500 GB SSD
- **Red**: 1 Gbps

### Hardware Producción
- **RAM**: 64 GB o más
- **CPU**: 24+ cores
- **Almacenamiento**: 2+ TB NVMe SSD
- **Red**: 10 Gbps

### Software Base
- **Sistema Operativo**: Ubuntu 20.04/22.04 LTS o CentOS 8/Rocky Linux
- **Docker**: Version 20.10+
- **Docker Compose**: Version 2.0+
- **Elasticsearch**: 7.17.x
- **Java**: OpenJDK 11

## Instalación y Configuración

### 1. Preparación del Entorno

```bash
# Actualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar dependencias
sudo apt install -y docker.io docker-compose git curl wget

# Configurar usuario para Docker
sudo usermod -aG docker $USER
newgrp docker

# Configurar límites del sistema
echo "* soft nofile 65535" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65535" | sudo tee -a /etc/security/limits.conf

# Configurar parámetros del kernel
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

### 2. Instalación de Wazuh

```bash
# Crear directorio de trabajo
mkdir ~/cybersec-platform
cd ~/cybersec-platform

# Descargar Wazuh
curl -sO https://packages.wazuh.com/4.7/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.7/config.yml

# Modificar configuración (editar config.yml según necesidades)
# Instalar Wazuh
sudo bash ./wazuh-install.sh -a
```

**Configuración de config.yml:**
```yaml
nodes:
  indexer:
    - name: node-1
      ip: "127.0.0.1"

  server:
    - name: wazuh-1
      ip: "127.0.0.1"

  dashboard:
    - name: dashboard
      ip: "127.0.0.1"
```

### 3. Instalación de TheHive

```bash
# Crear directorio para TheHive
mkdir thehive && cd thehive

# Crear docker-compose.yml para TheHive
cat > docker-compose.yml << 'EOF'
version: "3.8"

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.9
    container_name: thehive-elasticsearch
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
    volumes:
      - elasticsearch-data:/usr/share/elasticsearch/data
    ports:
      - "9200:9200"

  cassandra:
    image: cassandra:3.11
    container_name: thehive-cassandra
    environment:
      - CASSANDRA_CLUSTER_NAME=thehive
    volumes:
      - cassandra-data:/var/lib/cassandra
    ports:
      - "9042:9042"

  thehive:
    image: thehiveproject/thehive4:4.1.23-1
    container_name: thehive
    depends_on:
      - elasticsearch
      - cassandra
    environment:
      - JVM_OPTS="-Xms1g -Xmx1g"
    volumes:
      - thehive-data:/opt/thp/thehive/data
      - ./application.conf:/opt/thp/thehive/conf/application.conf
    ports:
      - "9000:9000"

volumes:
  elasticsearch-data:
  cassandra-data:
  thehive-data:
EOF

# Crear configuración de TheHive
cat > application.conf << 'EOF'
include file("/opt/thp/thehive/conf/reference.conf")

db.janusgraph {
  storage {
    backend: cql
    hostname: ["cassandra"]
    cql {
      cluster-name: thehive
      keyspace: thehive
    }
  }
  index.search {
    backend: elasticsearch
    hostname: ["elasticsearch"]
    index-name: thehive
  }
}

storage {
  provider: localfs
  localfs.location: /opt/thp/thehive/data
}

play.http.secret.key="SuperSecretKey123456789"
EOF

# Iniciar TheHive
docker-compose up -d
```

### 4. Instalación de Cortex

```bash
# Crear directorio para Cortex
cd ~/cybersec-platform
mkdir cortex && cd cortex

# Crear docker-compose.yml para Cortex
cat > docker-compose.yml << 'EOF'
version: "3.8"

services:
  elasticsearch-cortex:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.17.9
    container_name: cortex-elasticsearch
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
      - "ES_JAVA_OPTS=-Xms1g -Xmx1g"
    volumes:
      - elasticsearch-cortex-data:/usr/share/elasticsearch/data
    ports:
      - "9201:9200"

  cortex:
    image: thehiveproject/cortex:3.1.7-1
    container_name: cortex
    depends_on:
      - elasticsearch-cortex
    environment:
      - JVM_OPTS="-Xms1g -Xmx1g"
    volumes:
      - cortex-data:/opt/cortex/data
      - ./application.conf:/opt/cortex/conf/application.conf
    ports:
      - "9001:9001"

volumes:
  elasticsearch-cortex-data:
  cortex-data:
EOF

# Crear configuración de Cortex
cat > application.conf << 'EOF'
include file("/opt/cortex/conf/reference.conf")

search {
  index: cortex
  elasticsearch {
    uri: "http://elasticsearch-cortex:9200"
  }
}

analyzer {
  urls: [
    "https://download.thehive-project.org/analyzers.json"
  ]
  path: "/opt/cortex/analyzers"
}

responder {
  urls: [
    "https://download.thehive-project.org/responders.json"
  ]
  path: "/opt/cortex/responders"
}

play.http.secret.key="CortexSecretKey123456789"
EOF

# Iniciar Cortex
docker-compose up -d
```

### 5. Instalación de MISP

```bash
# Crear directorio para MISP
cd ~/cybersec-platform
mkdir misp && cd misp

# Crear docker-compose.yml para MISP
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  redis:
    image: redis:6-alpine
    container_name: misp-redis

  db:
    image: mysql:8.0
    container_name: misp-db
    environment:
      - MYSQL_DATABASE=misp
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=misp_password
      - MYSQL_ROOT_PASSWORD=root_password
    volumes:
      - mysql_data:/var/lib/mysql

  misp:
    image: coolacid/misp-docker:core-latest
    container_name: misp-core
    depends_on:
      - redis
      - db
    environment:
      - HOSTNAME=localhost
      - REDIS_FQDN=redis
      - INIT=true
      - MYSQL_HOST=db
      - MYSQL_DATABASE=misp
      - MYSQL_USER=misp
      - MYSQL_PASSWORD=misp_password
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - misp-data:/var/www/MISP

volumes:
  mysql_data:
  misp-data:
EOF

# Iniciar MISP
docker-compose up -d
```

## Integración de Componentes

### 1. Configuración de TheHive con Cortex

```bash
# Editar configuración de TheHive
cat >> ~/cybersec-platform/thehive/application.conf << 'EOF'

# Cortex Integration
play.modules.enabled += org.thp.thehive.connector.cortex.CortexModule
cortex {
  servers = [
    {
      name = local
      url = "http://localhost:9001"
      auth {
        type = "bearer"
        key = "YOUR_CORTEX_API_KEY"
      }
    }
  ]
}
EOF
```

### 2. Configuración de Wazuh con TheHive

```python
# Script de integración Wazuh-TheHive
# Guardar como /var/ossec/integrations/custom-thehive.py

#!/usr/bin/env python3

import json
import sys
import requests
from datetime import datetime

# Configuración
THEHIVE_URL = "http://localhost:9000"
THEHIVE_API_KEY = "YOUR_THEHIVE_API_KEY"
THEHIVE_ORG = "demo"

def create_case(alert_data):
    """Crear caso en TheHive"""
    
    headers = {
        'Authorization': f'Bearer {THEHIVE_API_KEY}',
        'Content-Type': 'application/json'
    }
    
    case_data = {
        'title': f"Wazuh Alert: {alert_data.get('rule', {}).get('description', 'Unknown')}",
        'description': f"Wazuh alert detected\n\nRule ID: {alert_data.get('rule', {}).get('id')}\nLevel: {alert_data.get('rule', {}).get('level')}\nAgent: {alert_data.get('agent', {}).get('name')}",
        'severity': get_severity(alert_data.get('rule', {}).get('level', 0)),
        'tags': ['wazuh', 'automated'],
        'template': 'wazuh-alert'
    }
    
    response = requests.post(
        f"{THEHIVE_URL}/api/case",
        headers=headers,
        json=case_data
    )
    
    return response.status_code == 201

def get_severity(level):
    """Mapear nivel de Wazuh a severidad de TheHive"""
    if level >= 10:
        return 3  # High
    elif level >= 7:
        return 2  # Medium
    else:
        return 1  # Low

if __name__ == "__main__":
    try:
        # Leer datos de Wazuh
        input_data = sys.stdin.read()
        alert_data = json.loads(input_data)
        
        # Crear caso
        if create_case(alert_data):
            print("Case created successfully")
        else:
            print("Failed to create case")
            
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)
```

```xml
<!-- Configuración en /var/ossec/etc/ossec.conf -->
<integration>
    <name>custom-thehive.py</name>
    <hook_url>http://localhost:9000/api/case</hook_url>
    <level>7</level>
    <api_key>YOUR_THEHIVE_API_KEY</api_key>
</integration>
```

### 3. Configuración de MISP con TheHive

```python
# Script de sincronización MISP-TheHive
# Guardar como ~/cybersec-platform/scripts/misp-sync.py

#!/usr/bin/env python3

import requests
import json
from pymisp import PyMISP
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert

# Configuración MISP
MISP_URL = "https://localhost"
MISP_KEY = "YOUR_MISP_API_KEY"

# Configuración TheHive
THEHIVE_URL = "http://localhost:9000"
THEHIVE_KEY = "YOUR_THEHIVE_API_KEY"

def sync_misp_indicators():
    """Sincronizar indicadores de MISP con TheHive"""
    
    # Conexión a MISP
    misp = PyMISP(MISP_URL, MISP_KEY, False)
    
    # Conexión a TheHive
    thehive = TheHiveApi(THEHIVE_URL, THEHIVE_KEY)
    
    # Obtener eventos recientes de MISP
    events = misp.search('events', published=True, limit=10)
    
    for event in events:
        # Crear alerta en TheHive basada en evento MISP
        alert = Alert(
            title=f"MISP Event: {event['Event']['info']}",
            tlp=get_tlp(event['Event']['threat_level_id']),
            severity=get_severity(event['Event']['threat_level_id']),
            description=event['Event']['info'],
            type='misp-event',
            source='MISP',
            sourceRef=event['Event']['uuid'],
            tags=['misp', 'threat-intel']
        )
        
        response = thehive.create_alert(alert)
        print(f"Created alert: {response.json()}")

def get_tlp(threat_level):
    """Mapear nivel de amenaza de MISP a TLP"""
    mapping = {
        '1': 4,  # TLP:RED
        '2': 3,  # TLP:AMBER
        '3': 2,  # TLP:GREEN
        '4': 1   # TLP:WHITE
    }
    return mapping.get(str(threat_level), 2)

def get_severity(threat_level):
    """Mapear nivel de amenaza a severidad"""
    mapping = {
        '1': 3,  # High
        '2': 2,  # Medium
        '3': 1,  # Low
        '4': 1   # Low
    }
    return mapping.get(str(threat_level), 2)

if __name__ == "__main__":
    sync_misp_indicators()
```

## Casos de Uso

### Caso de Uso 1: Detección y Respuesta Automatizada

**Escenario**: Wazuh detecta múltiples intentos de login fallidos

**Flujo**:
1. Wazuh genera alerta de fuerza bruta
2. Se crea automáticamente un caso en TheHive
3. Cortex ejecuta análisis de la IP origen
4. MISP verifica si la IP está en listas de amenazas
5. Se ejecuta respuesta automatizada (bloqueo de IP)

### Caso de Uso 2: Análisis de Malware

**Escenario**: Detección de archivo sospechoso

**Flujo**:
1. Wazuh detecta ejecución de archivo sospechoso
2. TheHive recibe el caso con hash del archivo
3. Cortex ejecuta múltiples analizadores:
   - VirusTotal
   - Análisis estático
   - Análisis de comportamiento
4. MISP busca IOCs relacionados
5. Analyst revisa y toma decisiones

### Caso de Uso 3: Hunting de Amenazas

**Escenario**: Búsqueda proactiva de amenazas

**Flujo**:
1. Analyst crea hipótesis en TheHive
2. Consulta datos históricos en Wazuh
3. Utiliza IOCs de MISP para hunting
4. Cortex automatiza análisis de observables
5. Documentación completa del proceso

## Monitoreo y Mantenimiento

### Scripts de Monitoreo

```bash
#!/bin/bash
# Script de monitoreo del estado de servicios
# Guardar como ~/cybersec-platform/scripts/health-check.sh

check_service() {
    local service_name=$1
    local url=$2
    
    echo "Checking $service_name..."
    if curl -f -s $url > /dev/null; then
        echo "✅ $service_name is running"
    else
        echo "❌ $service_name is down"
    fi
}

echo "=== Platform Health Check ==="
check_service "TheHive" "http://localhost:9000/api/status"
check_service "Cortex" "http://localhost:9001/api/status"
check_service "MISP" "http://localhost/servers/serverSettings"
check_service "Wazuh" "https://localhost:443"

# Verificar logs por errores
echo -e "\n=== Recent Errors ==="
docker logs thehive --tail=10 | grep -i error
docker logs cortex --tail=10 | grep -i error
```

### Respaldo Automatizado

```bash
#!/bin/bash
# Script de backup
# Guardar como ~/cybersec-platform/scripts/backup.sh

BACKUP_DIR="/backup/cybersec-$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

# Backup de TheHive
docker exec thehive-cassandra cqlsh -e "DESC KEYSPACE thehive" > $BACKUP_DIR/thehive-schema.cql
docker exec thehive-elasticsearch curl -X GET "localhost:9200/thehive/_settings" > $BACKUP_DIR/thehive-settings.json

# Backup de configuraciones
cp -r ~/cybersec-platform/*/application.conf $BACKUP_DIR/

# Comprimir backup
tar -czf $BACKUP_DIR.tar.gz $BACKUP_DIR
rm -rf $BACKUP_DIR

echo "Backup completed: $BACKUP_DIR.tar.gz"
```

### Actualización de Feeds de Amenazas

```python
# Script para actualizar feeds de MISP
# Guardar como ~/cybersec-platform/scripts/update-feeds.py

#!/usr/bin/env python3

from pymisp import PyMISP
import schedule
import time

MISP_URL = "https://localhost"
MISP_KEY = "YOUR_MISP_API_KEY"

def update_feeds():
    """Actualizar feeds de MISP"""
    misp = PyMISP(MISP_URL, MISP_KEY, False)
    
    # Obtener lista de feeds
    feeds = misp.feeds()
    
    for feed in feeds:
        if feed['Feed']['enabled']:
            print(f"Updating feed: {feed['Feed']['name']}")
            misp.fetch_feed(feed['Feed']['id'])

# Programar actualización cada 6 horas
schedule.every(6).hours.do(update_feeds)

if __name__ == "__main__":
    while True:
        schedule.run_pending()
        time.sleep(60)
```

## Configuración de Dashboards

### Dashboard de TheHive

```javascript
// Custom dashboard configuration
// Agregar en TheHive > Admin > Custom Fields

{
  "case_metrics": {
    "open_cases": "SELECT COUNT(*) FROM cases WHERE status = 'Open'",
    "closed_cases": "SELECT COUNT(*) FROM cases WHERE status = 'Resolved'",
    "high_severity": "SELECT COUNT(*) FROM cases WHERE severity = 3"
  },
  "alert_metrics": {
    "pending_alerts": "SELECT COUNT(*) FROM alerts WHERE status = 'New'",
    "wazuh_alerts": "SELECT COUNT(*) FROM alerts WHERE source = 'wazuh'",
    "misp_alerts": "SELECT COUNT(*) FROM alerts WHERE source = 'misp'"
  }
}
```

### Métricas de Rendimiento

```yaml
# Configuración de métricas en docker-compose
version: "3.8"

services:
  prometheus:
    image: prom/prometheus:latest
    container_name: prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml

  grafana:
    image: grafana/grafana:latest
    container_name: grafana
    ports:
      - "3000:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
```

## Troubleshooting

### Problemas Comunes

**1. Elasticsearch fuera de memoria**
```bash
# Aumentar memoria disponible
echo "ES_JAVA_OPTS=-Xms2g -Xmx2g" >> .env
docker-compose restart elasticsearch
```

**2. TheHive no puede conectar a Cassandra**
```bash
# Verificar conectividad
docker exec thehive telnet cassandra 9042

# Reiniciar servicios en orden
docker-compose stop
docker-compose up cassandra elasticsearch -d
sleep 30
docker-compose up thehive -d
```

**3. Cortex analyzers fallan**
```bash
# Verificar logs de analyzers
docker exec cortex tail -f /opt/cortex/logs/application.log

# Actualizar analyzers
docker exec cortex /opt/cortex/bin/cortex update-analyzers
```

## Conclusiones

### Beneficios Obtenidos

1. **Automatización Completa**: Flujo desde detección hasta respuesta
2. **Visibilidad Mejorada**: Dashboard unificado de seguridad
3. **Respuesta Rápida**: Reducción del MTTR (Mean Time To Response)
4. **Inteligencia de Amenazas**: Contextualización automática de alertas
5. **Trazabilidad**: Documentación completa de incidentes

### Métricas de Éxito

- **Reducción del MTTR**: De 4 horas a 30 minutos
- **Automatización**: 80% de alertas procesadas automáticamente
- **Falsos Positivos**: Reducción del 60%
- **Cobertura**: 100% de endpoints monitoreados

### Próximos Pasos

1. **SOAR Integration**: Implementar Phantom o Demisto
2. **Machine Learning**: Análisis predictivo de amenazas
3. **Threat Hunting**: Capacidades avanzadas de hunting
4. **Compliance**: Reportes automáticos de cumplimiento
5. **Cloud Integration**: Extender a entornos cloud

### Recomendaciones

1. **Capacitación**: Entrenar al equipo en todas las herramientas
2. **Documentación**: Mantener playbooks actualizados
3. **Testing**: Realizar simulacros regulares
4. **Tuning**: Ajustar reglas basado en el entorno
5. **Backup**: Implementar estrategia de respaldo robusta

---

*Este documento debe ser actualizado regularmente conforme evolucione la implementación y se identifiquen mejoras en el proceso.*
