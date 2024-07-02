import pyshark
import psutil

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
            port_id = getattr(cdp_packet, 'portid', 'N/A')
            vlan_nativa = getattr(cdp_packet, 'native_vlan', 'N/A')
            vlan_voice = getattr(cdp_packet, 'voice_vlan', 'N/A')
            
            # Verifica se já vimos este dispositivo
            if switch_name not in seen_devices:
                seen_devices.add(switch_name)
                print(f"\nEstamos atualmente conectados a: {switch_name} que é um(a): {switch_type} na porta: {port_id} com a VLAN: {vlan_nativa} e VLAN VOICE: {vlan_voice}")
                print("-" * 50)

if __name__ == "__main__":
    list_network_interfaces()
    interface = input("Digite o nome da interface de rede para captura: ")
    capture_cdp_packets(interface)
