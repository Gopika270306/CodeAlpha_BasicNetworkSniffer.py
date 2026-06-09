from scapy.all import sniff, IP, TCP, UDP, ICMP

def process_packet(packet):
    print("\n========================")

    if packet.haslayer(IP):
        ip = packet[IP]

        print("Source IP      :", ip.src)
        print("Destination IP :", ip.dst)

        if packet.haslayer(TCP):
            print("Protocol       : TCP")
            print("Source Port    :", packet[TCP].sport)
            print("Destination Port:", packet[TCP].dport)

        elif packet.haslayer(UDP):
            print("Protocol       : UDP")
            print("Source Port    :", packet[UDP].sport)
            print("Destination Port:", packet[UDP].dport)

        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")

sniff(prn=process_packet, store=False)
