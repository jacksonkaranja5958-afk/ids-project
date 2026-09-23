import threading
from collections import deque
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP

event_buffer = deque(maxlen=50)
buffer_lock = threading.Lock()


def _packet_handler(packet):
    """Called by Scapy for every captured packet; stores a summary in our buffer."""
    if IP in packet:
        if TCP in packet:
            proto = "TCP"
        elif UDP in packet:
            proto = "UDP"
        else:
            proto = "Other"

        event = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": packet[IP].src,
            "dest_ip": packet[IP].dst,
            "protocol": proto,
            "status": "Observed"
        }

        with buffer_lock:
            event_buffer.appendleft(event)


def _capture_loop():
    """Runs forever in a background thread, feeding packets to _packet_handler."""
    sniff(prn=_packet_handler, store=False)


def start_capture_thread():
    """Starts packet capture in a background daemon thread."""
    thread = threading.Thread(target=_capture_loop, daemon=True)
    thread.start()


def get_captured_events(limit=15):
    """Returns the most recent captured events, thread-safely."""
    with buffer_lock:
        return list(event_buffer)[:limit]

def get_protocol_breakdown():
    """Calculates real protocol percentages from currently captured packets."""
    with buffer_lock:
        events = list(event_buffer)

    if not events:
        return {"TCP": 0, "UDP": 0, "Other": 0}

    counts = {"TCP": 0, "UDP": 0, "Other": 0}
    for event in events:
        proto = event["protocol"]
        if proto in counts:
            counts[proto] += 1

    total = len(events)
    return {k: round((v / total) * 100, 1) for k, v in counts.items()}    