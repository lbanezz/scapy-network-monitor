# Sniffer de Rede Profissional v2 (Modo Ferramenta)
# Autor: Projeto educativo
# Requisitos: scapy, requests

from scapy.all import sniff, IP, TCP, UDP, Raw
from datetime import datetime
import threading
import json
import csv
import requests

# ================= CONFIG =================
LIMITE_ALERTA = 50
SALVAR_LOG = True
ARQUIVO_LOG_JSON = "logs_rede.json"
ARQUIVO_LOG_CSV = "logs_rede.csv"
GEOLOCATION = False  # True para ativar consulta de IP

ips_monitorados = {}
logs = []

# ================= GEO IP =================
def buscar_geo(ip):
    try:
        resposta = requests.get(f"http://ip-api.com/json/{ip}").json()
        return f"{resposta.get('country')} - {resposta.get('city')}"
    except:
        return "Desconhecido"

# ================= LOG =================
def salvar_logs():
    if not SALVAR_LOG:
        return

    with open(ARQUIVO_LOG_JSON, "w") as f:
        json.dump(logs, f, indent=4)

    with open(ARQUIVO_LOG_CSV, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["hora", "src", "dst", "protocolo", "alerta"])
        writer.writeheader()
        writer.writerows(logs)

# ================= ANALISE =================
def analisar_pacote(pkt):
    try:
        if pkt.haslayer(IP):
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
            protocolo = "OUTRO"

            if pkt.haslayer(TCP):
                protocolo = "TCP"
            elif pkt.haslayer(UDP):
                protocolo = "UDP"

            ips_monitorados[ip_src] = ips_monitorados.get(ip_src, 0) + 1

            alerta = ""
            if ips_monitorados[ip_src] > LIMITE_ALERTA:
                alerta = "POSSIVEL_ATAQUE"

            geo = ""
            if GEOLOCATION:
                geo = buscar_geo(ip_src)

            log = {
                "hora": str(datetime.now()),
                "src": ip_src,
                "dst": ip_dst,
                "protocolo": protocolo,
                "alerta": alerta
            }

            logs.append(log)

            print("="*60)
            print(f"Hora: {log['hora']}")
            print(f"Origem: {ip_src} {geo}")
            print(f"Destino: {ip_dst}")
            print(f"Protocolo: {protocolo}")
            print(f"Contagem: {ips_monitorados[ip_src]}")

            if pkt.haslayer(Raw):
                dados = pkt[Raw].load
                if b"login" in dados or b"password" in dados:
                    print("ALERTA: possivel credencial detectada")

            if alerta:
                print("ALERTA DE SEGURANCA:", alerta)

    except Exception as e:
        print("Erro:", e)

# ================= THREAD SALVAMENTO =================
def salvar_periodicamente():
    while True:
        salvar_logs()

# ================= MAIN =================
def iniciar():
    print("Sniffer Profissional Iniciado...")

    thread = threading.Thread(target=salvar_periodicamente, daemon=True)
    thread.start()

    sniff(prn=analisar_pacote, store=False)

if __name__ == "__main__":
    iniciar()
