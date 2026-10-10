import Foundation

/// The built-in port list behind `AskDetails.service`: IANA well-known services that matter on a developer Mac,
/// plus ports that dev servers, databases and local tools use by convention. Curated, not exhaustive.
public enum KnownPorts {
    /// The entry for `port`; `name` is `nil` when the port is in no list.
    public static func service(_ port: UInt16) -> KnownService {
        KnownService(port: port, name: names[port])
    }

    public static func name(_ port: UInt16) -> String? { names[port] }

    public static let names: [UInt16: String] = [
        // Internet services
        20: "FTP data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 43: "WHOIS", 53: "DNS", 67: "DHCP", 69: "TFTP",
        80: "HTTP", 88: "Kerberos", 110: "POP3", 119: "NNTP", 123: "NTP", 135: "MS RPC", 137: "NetBIOS", 139: "SMB (NetBIOS)",
        143: "IMAP", 161: "SNMP", 179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE (VPN)",
        514: "Syslog", 515: "LPD printing", 548: "AFP", 554: "RTSP", 587: "SMTP submission", 631: "IPP printing", 636: "LDAPS",
        853: "DNS over TLS", 873: "rsync", 989: "FTPS data", 990: "FTPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS proxy",
        1194: "OpenVPN", 1433: "SQL Server", 1521: "Oracle DB", 1701: "L2TP", 1723: "PPTP", 1812: "RADIUS", 1883: "MQTT",
        1900: "SSDP", 1935: "RTMP", 2049: "NFS", 2181: "ZooKeeper", 2222: "SSH (alt)", 3128: "HTTP proxy", 3260: "iSCSI",
        3268: "LDAP catalog", 3283: "Apple Remote Desktop", 3306: "MySQL", 3389: "Remote Desktop", 3478: "STUN/TURN",
        3690: "Subversion", 4369: "Erlang EPMD", 4500: "IPsec NAT-T", 5060: "SIP", 5061: "SIP over TLS", 5222: "XMPP",
        5223: "Apple Push", 5228: "Google Push", 5353: "mDNS", 5432: "PostgreSQL", 5671: "AMQP over TLS", 5672: "AMQP",
        5900: "VNC / Screen Sharing", 5984: "CouchDB", 6000: "X11", 6379: "Redis", 6443: "Kubernetes API", 6667: "IRC",
        6697: "IRC over TLS", 7687: "Neo4j Bolt", 8008: "HTTP (alt)", 8080: "HTTP (alt)", 8088: "HTTP (alt)",
        8443: "HTTPS (alt)", 8883: "MQTT over TLS", 9418: "Git", 9443: "HTTPS (alt)", 11211: "Memcached",
        41641: "Tailscale", 51820: "WireGuard",
        // Development servers and tools
        1313: "Hugo", 2375: "Docker API", 2376: "Docker API (TLS)", 2379: "etcd", 3000: "Dev server", 3001: "Dev server",
        4000: "Dev server", 4040: "Spark UI", 4200: "Angular dev server", 4222: "NATS", 4317: "OpenTelemetry gRPC",
        4318: "OpenTelemetry HTTP", 4443: "HTTPS (alt)", 5000: "Dev server", 5001: "Dev server", 5005: "Java debugger",
        5173: "Vite", 5174: "Vite", 5555: "Android Debug Bridge", 6006: "Storybook", 7077: "Spark", 7474: "Neo4j",
        7860: "Gradio", 8000: "Dev server", 8001: "Dev server", 8081: "Dev server", 8086: "InfluxDB", 8123: "Home Assistant",
        8200: "Vault", 8384: "Syncthing", 8500: "Consul", 8501: "Streamlit", 8545: "Ethereum RPC", 8888: "Jupyter",
        9000: "Dev server", 9001: "Dev server", 9042: "Cassandra", 9090: "Prometheus", 9092: "Kafka", 9093: "Alertmanager",
        9100: "Node exporter", 9200: "Elasticsearch", 9229: "Node inspector", 9300: "Elasticsearch nodes", 11434: "Ollama",
        15672: "RabbitMQ admin", 19000: "Expo", 22000: "Syncthing", 25565: "Minecraft", 27017: "MongoDB", 32400: "Plex",
        50051: "gRPC",
    ]
}
