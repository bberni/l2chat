from scapy.all import *

identifier = b'JEBACKRZYSIA'
def callback(packet):
    global identifier
    if packet.haslayer(Raw):
        payload = packet[Raw].load
        if payload.startswith(identifier):
            payload = [x.decode() for x in payload.split(b"\x00")]
            username, msg = payload[0][len(identifier):], payload[1]
            print(f"{username} said: {msg}")

# Replace 'ethernet' with the appropriate interface name
sniff(iface="eth0", prn=callback, store=0)