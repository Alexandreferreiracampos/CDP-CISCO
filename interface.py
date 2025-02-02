import pyshark
import psutil
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import asyncio
import os
import sys
from datetime import datetime  # Importando a biblioteca datetime para pegar a data e hora

def get_tshark_path():
    # Obtém o caminho para o diretório onde este script está sendo executado
    base_path = os.path.abspath(os.path.dirname(sys.argv[0]))
    
    tshark_path = os.path.join(base_path, 'tshark', 'tshark.exe')
    
    return tshark_path

# Configura o caminho para o TShark
pyshark.tshark.tshark_path = get_tshark_path()


# Função para listar interfaces de rede disponíveis
def list_network_interfaces():
    interfaces = psutil.net_if_addrs()
    return interfaces.keys()

# Função para capturar pacotes CDP
def capture_cdp_packets(interface):
    seen_devices = set()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    capture = pyshark.LiveCapture(interface=interface, bpf_filter='ether[20:2] == 0x2000')
    
    print(f"Capturando pacotes CDP na interface {interface}")
    
    # Atualiza o texto de carregamento
    loading_label.config(text="Capturando pacotes CDP, Aguarde...")
    root.update_idletasks()  # Atualiza a interface gráfica
    
    for packet in capture.sniff_continuously():
        if 'CDP' in packet:
            cdp_packet = packet['CDP']
            switch_name = getattr(cdp_packet, 'deviceid', 'N/A')
            ip_sw = getattr(cdp_packet, 'nrgyz_ip_address', 'N/A')
            switch_type = getattr(cdp_packet, 'platform', 'N/A')
            port_id = getattr(cdp_packet, 'portid', 'N/A')
            vlan_nativa = getattr(cdp_packet, 'native_vlan', 'N/A')
            vlan_voice = getattr(cdp_packet, 'voice_vlan', 'N/A')
            
            # Verifica se já vimos este dispositivo
            if switch_name not in seen_devices:
                seen_devices.add(switch_name)
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")  # Obtém a data e hora atual
                message = f"[{timestamp}]\nSW: {switch_name}\nIP: {ip_sw}\nPORTA: {port_id}\nVLAN: {vlan_nativa}\nVLAN VOICE: {vlan_voice}\nMODELO: {switch_type}"
                display_info(message)
                display_info("-" * 40)
                loading_label.config(text="Informações capturadas:")
                root.update_idletasks()  # Atualiza a interface gráfica
                log(message)


# Função para iniciar a captura de pacotes
def start_capture():
    selected_interface = interface_combobox.get()
    if selected_interface:
        capture_thread = threading.Thread(target=capture_cdp_packets, args=(selected_interface,))
        capture_thread.daemon = True
        capture_thread.start()
    else:
        messagebox.showwarning("Seleção de Interface", "Selecione uma interface.")

# Função para exibir informações na área de texto
def display_info(info):
    result_text.insert(tk.END, info + "\n")
    result_text.see(tk.END)

def log(value):
    log_file_patch = "Switch.txt"
    with open(log_file_patch, "r") as log_file:
        linhas = log_file.readlines()

    if len(linhas) >= 50000:
        linhas = linhas[-49999:]

    linhas.append(value + "\n\n")

    with open(log_file_patch, "w") as log_file:
        log_file.writelines(linhas)

# Interface Gráfica
root = tk.Tk()
root.title("Captura de Pacotes CDP")
root.geometry("400x450")


frame = ttk.Frame(root, padding="2")
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

your_name_label = ttk.Label(frame, text="Desenvolvido por: Alexandre Campos")
your_name_label.grid(column=0, row=3, columnspan=3, sticky=tk.S)

loading_label = ttk.Label(frame, text="Clique em 'Iniciar Captura' para carregar as informações.")
loading_label.grid(column=0, row=1, columnspan=3, sticky=tk.N)

ttk.Label(frame, text="Selecione a Interface:").grid(column=0, row=0, sticky=tk.W)
interfaces = list_network_interfaces()
interface_combobox = ttk.Combobox(frame, values=list(interfaces))
interface_combobox.grid(column=1, row=0, sticky=(tk.W, tk.E))

start_button = ttk.Button(frame, text="Iniciar Captura", command=start_capture)
start_button.grid(column=2, row=0, sticky=tk.W)

result_text = tk.Text(frame, wrap="word", height=20, width=40)
result_text.grid(column=0, row=2, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))

scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=result_text.yview)
result_text['yscrollcommand'] = scrollbar.set
scrollbar.grid(column=3, row=1, sticky=(tk.N, tk.S))

frame.columnconfigure(1, weight=1)
frame.rowconfigure(1, weight=1)

root.mainloop()
