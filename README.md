# 🔐 Network Security Sniffer (Python + Scapy)

Ferramenta de monitoramento de rede em tempo real desenvolvida em Python utilizando Scapy.
O projeto simula um sistema básico de detecção de intrusão (IDS), capturando e analisando pacotes de rede diretamente pelo terminal.

---

## 🚀 Funcionalidades

* 📡 Captura de pacotes em tempo real
* 🌐 Identificação de IP de origem e destino
* 🔍 Detecção de protocolo (TCP/UDP)
* 🚨 Identificação de comportamento suspeito (flood simples)
* 🔐 Detecção básica de possíveis credenciais em tráfego
* 💾 Exportação automática de logs:

  * JSON (análise)
  * CSV (relatórios)
* 📊 Contagem de pacotes por IP
* 🌍 (Opcional) Geolocalização de IP via API

---

## 🛠️ Tecnologias utilizadas

* Python
* Scapy
* Requests
* JSON / CSV

---

## 📦 Instalação

Clone o repositório:

```bash
git clone https://github.com/lbanezz/scapy-network-monitor.git
cd seu-repositorio
```

Instale as dependências:

```bash
pip install scapy requests
```

---

## ▶️ Como executar

```bash
python sniffer.py
```

---

## ⚙️ Configuração

No código, você pode alterar:

```python
LIMITE_ALERTA = 50          # Quantidade de pacotes para gerar alerta
SALVAR_LOG = True           # Ativar ou desativar logs
GEOLOCATION = False         # Ativar geolocalização de IP
```

---

## 📊 Exemplo de saída no terminal

```
============================================================
Hora: 2026-04-05 12:00:00
Origem: 192.168.0.10
Destino: 8.8.8.8
Protocolo: TCP
Contagem: 55
ALERTA DE SEGURANCA: POSSIVEL_ATAQUE
```

---

## 📁 Exemplo de log (JSON)

```json
{
  "hora": "2026-04-05 12:00:00",
  "src": "192.168.0.10",
  "dst": "8.8.8.8",
  "protocolo": "TCP",
  "alerta": "POSSIVEL_ATAQUE"
}
```

---

## ⚠️ Requisitos importantes

* Executar como administrador/root
* No Windows, instalar o Npcap:
  https://nmap.org/npcap/

---

## 💡 Objetivo do projeto

Simular um sistema básico de detecção de intrusão (IDS) para fins educacionais, permitindo a análise de tráfego de rede e identificação de possíveis comportamentos suspeitos.

---

## 🔐 Aviso

Esta ferramenta é destinada apenas para fins educacionais e uso em ambientes autorizados.
Não utilize em redes sem permissão.

---

## 👨‍💻 Autor

David Reis
