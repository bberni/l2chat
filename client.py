from scapy.all import *

class Message(Packet):
    fields_desc = [
        StrField("username", "anonymous"),
        ByteField("null", 0),
        StrField("msg", "")
    ]

src_MAC = "00:0c:29:4b:43:b0" #insert your mac address here
dst_MAC = "ff:ff:ff:ff:ff:ff"

eth_frame = Ether(dst=dst_MAC, src=src_MAC)
identifier = b"L2CHAT"

username = input("Enter your username: ")
while True: 
    msg = input("> ")
    packet = eth_frame / Raw(identifier) / Raw(Message(username=username, msg=msg))
    sendp(packet, verbose=False)

