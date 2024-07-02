import pyshark
import psutil
import tkinter as tk
from tkinter import ttk, messagebox
import threading
import asyncio

def list_network_interfaces():
    interfaces = psutil.net_if_addrs()
    return interfaces.keys()

def capture_cdp_packets(interface):
    seen_devices = set()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    capture = pyshark.LiveCapture(interface=interface, bpf_filter='ether[20:2] == 0x2000')
    
    print(f"Capturando pacotes CDP na interface {interface}")
    
    for packet in capture.sniff_continuously():
        if 'CDP' in packet:
            cdp_packet = packet['CDP']
            switch_name = getattr(cdp_packet, 'deviceid', 'N/A')
            switch_type = getattr(cdp_packet, 'platform', 'N/A')
            port_id = getattr(cdp_packet, 'portid', 'N/A')
            vlan_nativa = getattr(cdp_packet, 'native_vlan', 'N/A')
            vlan_voice = getattr(cdp_packet, 'voice_vlan', 'N/A')
            
            # Verifica se já vimos este dispositivo
            if switch_name not in seen_devices:
                seen_devices.add(switch_name)
                message = f"SW: {switch_name}\nPORTA: {port_id}\nVLAN: {vlan_nativa}\nVLAN VOICE: {vlan_voice}\nMODELO: {switch_type}"
                display_info(message)


def start_capture():
    selected_interface = interface_combobox.get()
    if selected_interface:
        capture_thread = threading.Thread(target=capture_cdp_packets, args=(selected_interface,))
        capture_thread.daemon = True
        capture_thread.start()
    else:
        messagebox.showwarning("Seleção de Interface", "Selecione uma interface.")

def display_info(info):
    result_text.insert(tk.END, info + "\n")
    result_text.see(tk.END)

# Interface Gráfica
root = tk.Tk()
root.title("Captura de Pacotes CDP")
root.geometry("400x400")

frame = ttk.Frame(root, padding="2")
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Label
ttk.Label(frame, text="Selecione a Interface:").grid(column=0, row=0, sticky=tk.W)

# Combobox
interfaces = list_network_interfaces()
interface_combobox = ttk.Combobox(frame, values=list(interfaces))
interface_combobox.grid(column=1, row=0, sticky=(tk.W, tk.E))

# Botão para Iniciar Captura
start_button = ttk.Button(frame, text="Iniciar Captura", command=start_capture)
start_button.grid(column=2, row=0, sticky=tk.W)

# Área de Texto para Resultados
result_text = tk.Text(frame, wrap="word", height=20, width=40)
result_text.grid(column=0, row=1, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S))

# Scrollbar para o Texto
scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=result_text.yview)
result_text['yscrollcommand'] = scrollbar.set
scrollbar.grid(column=3, row=1, sticky=(tk.N, tk.S))

# Configuração de Grid
frame.columnconfigure(1, weight=1)
frame.rowconfigure(1, weight=1)

root.mainloop()
