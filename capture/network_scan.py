import socket
from scapy.all import ARP, Ether, srp


def get_local_subnet():
    """Detects the local machine's subnet (e.g. 192.168.1.0/24)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    finally:
        s.close()
    subnet = ".".join(local_ip.split(".")[:3]) + ".0/24"
    return subnet


def scan_devices(timeout=3):
    """Sends ARP requests across the local subnet and returns responding devices."""
    subnet = get_local_subnet()

    arp_request = ARP(pdst=subnet)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast / arp_request

    answered, _ = srp(packet, timeout=timeout, verbose=0)

    devices = []
    for sent, received in answered:
        try:
            hostname = socket.gethostbyaddr(received.psrc)[0]
        except (socket.herror, socket.gaierror):
            hostname = "Unknown"

        devices.append({
            "hostname": hostname,
            "ip": received.psrc,
            "mac": received.hwsrc,
            "os": "Unknown",
            "status": "Online"
        })

    return devices