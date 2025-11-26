# 🛡️ IOC Checker Pro - VirusTotal Analysis Tool

Aplicación web avanzada para el análisis de Indicadores de Compromiso (IOCs) en tiempo real utilizando la API v3 de VirusTotal. 

Esta herramienta ha sido rediseñada para ofrecer una experiencia de usuario fluida, gestión inteligente de límites de API (Rate Limiting) y clasificación automática de amenazas.

![IOC Checker Preview](https://raw.githubusercontent.com/CCDani/IOC-Checker-Pro/refs/heads/main/Captura.PNG)


## 🚀 Características Principales

### 🧠 Motor de Análisis Inteligente
- **Modo Inteligente (Regex):** Pega un texto completo (logs, correos, informes) y la herramienta extraerá automáticamente:
  - Hashes (MD5, SHA1, SHA256)
  - Direcciones IP (IPv4)
  - Dominios
  - URLs
- **Modo Lista:** Procesa IOCs línea por línea para listas limpias.

### 📊 Interfaz Dinámica y Resultados
- **Tabla Interactiva:** Ordena los resultados por gravedad, tipo de IOC o número de detecciones haciendo clic en los encabezados.
- **Detección de Tipos:** Clasifica automáticamente si es un Archivo, URL, Dominio o IP.
- **Enlaces Directos (Deep Linking):** Genera enlaces precisos al reporte específico en VirusTotal (usando IDs y Hashes correctos) para ver el detalle de la amenaza.
- **Indicadores Visuales:** Badges de colores para identificar rápidamente el estado:
  - 🟢 Limpio
  - 🟡 Sospechoso
  - 🔴 Malicioso

### ⏱️ Gestión de Rate Limiting (API Gratuita)
- **Protección de Cuenta:** Sistema de pausa configurable entre peticiones.
- **Recomendación Integrada:** Tooltip informativo con los límites de la cuenta gratuita (4 peticiones/minuto, 500/día).
- **Contador de Sesión:** Monitorea cuántos IOCs has consumido en tu sesión actual para no exceder tu cuota diaria.

---

## 🛠️ Requisitos Técnicos

- **Python:** 3.8 o superior
- **Backend:** Flask
- **Librerías:** `requests`
- **Frontend:** HTML5, CSS3, JavaScript (Vanilla) + FontAwesome

---

## 💻 Instalación Local

Si deseas ejecutar la herramienta en tu máquina local:

1. **Clonar el repositorio:**
   ```bash
   git clone https://github.com/CCDani/IOC-Checker-Pro
   ```


2. **Crear un entorno virtual:**


    ```bash
    python -m venv env
    ```
3.  **Activa el entorno: (En Windows)**

    ```bash
    .\env\Scripts\activate
    ```


4. **Instalar dependencias:**

    ```Bash
    pip install Flask requests
    ```

5. **Ejecutar la aplicación:**

    ```Bash
    python app.py
    ```

Abre tu navegador en http://127.0.0.1:5000


## 📖 Guía de Uso
API Key: Obtén tu API Key gratuita registrándote en VirusTotal.

**Configurar Pausa:** Si tienes cuenta Free, deja el valor en 16 segundos.

Si tienes cuenta Premium, puedes bajarlo a 0.

Ingresar Datos: Pega el texto o la lista de IOCs.

Analizar: Pulsa el botón y observa el progreso en tiempo real.


🤝 Atribución
Iconos:
UI Icons por FontAwesome.
Favicon "Malware" diseñado por Vlad Szirka - Flaticon.

## Nota Legal: Esta herramienta utiliza la API pública de VirusTotal. Asegúrate de cumplir con sus Términos de Servicio. No nos hacemos responsables del uso indebido de la herramienta.

## 💻 Colaboración: Proyecto de código abierto para la comunidad de ciberseguridad.
