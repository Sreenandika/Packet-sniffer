from scapy.all import sniff, DNS, DNSQR

def packet_callback(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:  # DNS query (not response)
        query = packet[DNSQR].qname.decode("utf-8")
        print(f" You are visiting: {query}")

print("Sniffer started... now open your browser and visit some sites!")
sniff(prn=packet_callback, store=0)
