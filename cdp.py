import pyshark
import psutil

import os
import sys

def get_tshark_path():
    # Obtém o caminho para o diretório onde este script está sendo executado
    base_path = os.path.abspath(os.path.dirname(sys.argv[0]))
    
    # Assumindo que o tshark.exe está na pasta 'tshark' dentro do diretório do executável
    tshark_path = os.path.join(base_path, 'tshark', 'tshark.exe')
    
    return tshark_path

# Configura o caminho para o TShark
pyshark.tshark.tshark_path = get_tshark_path()

def list_network_interfaces():
    interfaces = psutil.net_if_addrs()
    print("Interfaces de rede disponíveis:")
    for interface in interfaces:
        print(f"- {interface}")

def capture_cdp_packets(interface):
    seen_devices = set()
    capture = pyshark.LiveCapture(interface=interface, bpf_filter='ether[20:2] == 0x2000')
    
    print(f"Capturando pacotes CDP na interface {interface}")
    
    for packet in capture.sniff_continuously():
        if 'CDP' in packet:
            cdp_packet = packet['CDP']
            switch_name = getattr(cdp_packet, 'deviceid', 'N/A')
            switch_type = getattr(cdp_packet, 'platform', 'N/A')
            ip_sw = getattr(cdp_packet, 'nrgyz_ip_address', 'N/A')
            port_id = getattr(cdp_packet, 'portid', 'N/A')
            vlan_nativa = getattr(cdp_packet, 'native_vlan', 'N/A')
            vlan_voice = getattr(cdp_packet, 'voice_vlan', 'N/A')
            
            # Verifica se já vimos este dispositivo
            if switch_name not in seen_devices:
                seen_devices.add(switch_name)
                print(f"SW: {switch_name}\nIP: {ip_sw}\nPORTA: {port_id}\nVLAN: {vlan_nativa}\nVLAN VOICE: {vlan_voice}\nMODELO: {switch_type}")
                print("-" * 50)

if __name__ == "__main__":
    list_network_interfaces()
    interface = input("Digite o nome da interface de rede para captura: ")
    capture_cdp_packets(interface)
