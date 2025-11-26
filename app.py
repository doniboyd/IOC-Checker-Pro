from flask import Flask, request, jsonify, render_template
import requests

app = Flask(__name__)

@app.route('/', methods=['GET'])
def index():
    return render_template("index.html")

@app.route('/consultar', methods=['POST'])
def consultar_virus_total():
    data = request.json
    ioc = data.get('ioc')
    api_key = data.get('apiKey')

    if not ioc or not api_key:
        return jsonify({'error': 'Falta el IOC o la API Key'}), 400

    # Usamos el endpoint de search que es versátil
    url = f'https://www.virustotal.com/api/v3/search?query={ioc}'
    
    headers = {
        'x-apikey': api_key,
        'User-Agent': 'IOC-Checker-Tool/1.0' # Buena práctica identificar el cliente
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            return jsonify(response.json())
        elif response.status_code == 429:
            return jsonify({'error': 'Límite de API excedido (Rate Limit)'}), 429
        elif response.status_code == 401:
            return jsonify({'error': 'API Key inválida'}), 401
        elif response.status_code == 404:
            return jsonify({'data': []}), 200 # No encontrado, devolvemos data vacía
        else:
            return jsonify({'error': f'Error de VirusTotal: {response.status_code}'}), response.status_code

    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Error de conexión: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True)