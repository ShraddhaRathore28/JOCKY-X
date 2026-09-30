from .models import Event
def sample_events():
    return [
    Event(timestamp="2026-09-30T10:00:00Z",platform="windows",event_type="process_start",process="powershell.exe",parent_process="winword.exe"),
    Event(timestamp="2026-09-30T10:00:05Z",platform="windows",event_type="network_connection",destination="203.0.113.20:443"),
    Event(timestamp="2026-09-30T10:00:15Z",platform="windows",event_type="network_connection",destination="203.0.113.20:443"),
    Event(timestamp="2026-09-30T10:00:25Z",platform="windows",event_type="network_connection",destination="203.0.113.20:443"),
    Event(timestamp="2026-09-30T10:00:35Z",platform="windows",event_type="network_connection",destination="203.0.113.20:443"),
    Event(timestamp="2026-09-30T10:01:00Z",platform="windows",event_type="dns_query",domain="encoded-long-subdomain.example.test"),
    Event(timestamp="2026-09-30T10:01:10Z",platform="windows",event_type="file_write",file_path="C:/Users/Demo/AppData/Local/demo.tmp"),
    Event(timestamp="2026-09-30T10:02:00Z",platform="windows",event_type="memory_anomaly",details={"anomalous":True}),
    Event(timestamp="2026-09-30T10:03:00Z",platform="windows",event_type="network_connection",destination="10.0.0.20:445"),
    Event(timestamp="2026-09-30T10:03:05Z",platform="windows",event_type="network_connection",destination="10.0.0.21:445"),
    Event(timestamp="2026-09-30T10:03:10Z",platform="windows",event_type="network_connection",destination="10.0.0.22:445"),
    Event(timestamp="2026-09-30T10:04:00Z",platform="windows",event_type="network_connection",destination="198.51.100.50:443",bytes_out=8000000)]
