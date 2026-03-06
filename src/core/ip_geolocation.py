"""
IP Geolocation module for tracking intrusion sources.

Provides geographic location information for IP addresses,
including country, city, coordinates, and ISP details.
"""

import json
import socket
import time
from typing import Dict, Optional
from urllib import request, error
import random


class IPGeocoder:
    """Geocode IP addresses to determine geographic location.
    
    Uses multiple free geolocation services with fallback support.
    Includes caching to minimize API calls and rate limiting.
    """
    
    def __init__(self, cache_size: int = 500):
        """Initialize the geocoder with cache.
        
        Parameters
        ----------
        cache_size : int
            Maximum number of IPs to cache location data for.
        """
        self._cache: Dict[str, dict] = {}
        self._cache_size = cache_size
        self._last_request_time = 0
        self._min_request_interval = 1.0  # Minimum seconds between API calls
        
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is a private/local address."""
        try:
            # Convert IP to integer for comparison
            parts = ip.split('.')
            if len(parts) != 4:
                return True
            
            first_octet = int(parts[0])
            second_octet = int(parts[1])
            
            # Check private IP ranges
            if first_octet == 10:  # 10.0.0.0/8
                return True
            if first_octet == 172 and 16 <= second_octet <= 31:  # 172.16.0.0/12
                return True
            if first_octet == 192 and second_octet == 168:  # 192.168.0.0/16
                return True
            if first_octet == 127:  # 127.0.0.0/8 (localhost)
                return True
            if first_octet == 169 and second_octet == 254:  # 169.254.0.0/16 (link-local)
                return True
            
            return False
        except (ValueError, IndexError):
            return True
    
    def _fetch_from_ipapi(self, ip: str) -> Optional[dict]:
        """Fetch location data from ip-api.com (free, no key needed)."""
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
            
            req = request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0')
            
            with request.urlopen(req, timeout=3) as response:
                data = json.loads(response.read().decode())
                
                if data.get('status') == 'success':
                    return {
                        'ip': data.get('query', ip),
                        'country': data.get('country', 'Unknown'),
                        'country_code': data.get('countryCode', 'XX'),
                        'region': data.get('regionName', 'Unknown'),
                        'city': data.get('city', 'Unknown'),
                        'zip': data.get('zip', ''),
                        'latitude': data.get('lat', 0.0),
                        'longitude': data.get('lon', 0.0),
                        'timezone': data.get('timezone', ''),
                        'isp': data.get('isp', 'Unknown'),
                        'org': data.get('org', 'Unknown'),
                        'as': data.get('as', 'Unknown'),
                    }
        except (error.URLError, error.HTTPError, json.JSONDecodeError, Exception):
            pass
        
        return None
    
    def _generate_simulated_location(self, ip: str) -> dict:
        """Generate realistic simulated location data for testing."""
        # List of realistic attack source locations
        locations = [
            {'country': 'China', 'country_code': 'CN', 'city': 'Beijing', 'lat': 39.9042, 'lon': 116.4074},
            {'country': 'Russia', 'country_code': 'RU', 'city': 'Moscow', 'lat': 55.7558, 'lon': 37.6173},
            {'country': 'United States', 'country_code': 'US', 'city': 'Los Angeles', 'lat': 34.0522, 'lon': -118.2437},
            {'country': 'Brazil', 'country_code': 'BR', 'city': 'São Paulo', 'lat': -23.5505, 'lon': -46.6333},
            {'country': 'India', 'country_code': 'IN', 'city': 'Mumbai', 'lat': 19.0760, 'lon': 72.8777},
            {'country': 'Germany', 'country_code': 'DE', 'city': 'Frankfurt', 'lat': 50.1109, 'lon': 8.6821},
            {'country': 'Ukraine', 'country_code': 'UA', 'city': 'Kyiv', 'lat': 50.4501, 'lon': 30.5234},
            {'country': 'United Kingdom', 'country_code': 'GB', 'city': 'London', 'lat': 51.5074, 'lon': -0.1278},
            {'country': 'France', 'country_code': 'FR', 'city': 'Paris', 'lat': 48.8566, 'lon': 2.3522},
            {'country': 'Netherlands', 'country_code': 'NL', 'city': 'Amsterdam', 'lat': 52.3676, 'lon': 4.9041},
            {'country': 'Romania', 'country_code': 'RO', 'city': 'Bucharest', 'lat': 44.4268, 'lon': 26.1025},
            {'country': 'Turkey', 'country_code': 'TR', 'city': 'Istanbul', 'lat': 41.0082, 'lon': 28.9784},
            {'country': 'South Korea', 'country_code': 'KR', 'city': 'Seoul', 'lat': 37.5665, 'lon': 126.9780},
            {'country': 'Vietnam', 'country_code': 'VN', 'city': 'Hanoi', 'lat': 21.0285, 'lon': 105.8542},
            {'country': 'Poland', 'country_code': 'PL', 'city': 'Warsaw', 'lat': 52.2297, 'lon': 21.0122},
        ]
        
        # Use IP address to deterministically select location (consistent results)
        try:
            ip_hash = sum(ord(c) for c in ip)
            location = locations[ip_hash % len(locations)]
        except:
            location = random.choice(locations)
        
        return {
            'ip': ip,
            'country': location['country'],
            'country_code': location['country_code'],
            'region': location.get('region', 'N/A'),
            'city': location['city'],
            'zip': '',
            'latitude': location['lat'] + random.uniform(-0.5, 0.5),  # Small variation
            'longitude': location['lon'] + random.uniform(-0.5, 0.5),
            'timezone': 'Simulated',
            'isp': f"ISP-{random.randint(1000, 9999)}",
            'org': f"Organization {random.randint(100, 999)}",
            'as': f"AS{random.randint(10000, 99999)}",
            'simulated': True,
        }
    
    def geocode(self, ip: str, use_simulation: bool = False) -> dict:
        """Get geographic location for an IP address.
        
        Parameters
        ----------
        ip : str
            IP address to geocode.
        use_simulation : bool
            If True, generate simulated data instead of real API calls.
            Useful for testing without rate limits.
        
        Returns
        -------
        dict
            Location information including country, city, coordinates, etc.
        """
        # Check cache first
        if ip in self._cache:
            return self._cache[ip]
        
        # Handle private/local IPs
        if self._is_private_ip(ip):
            location = {
                'ip': ip,
                'country': 'Local Network',
                'country_code': 'LN',
                'region': 'Private',
                'city': 'Local',
                'zip': '',
                'latitude': 0.0,
                'longitude': 0.0,
                'timezone': 'Local',
                'isp': 'Local Network',
                'org': 'Private Network',
                'as': 'N/A',
                'private': True,
            }
        elif use_simulation:
            # Use simulated data
            location = self._generate_simulated_location(ip)
        else:
            # Rate limiting
            current_time = time.time()
            time_since_last_request = current_time - self._last_request_time
            if time_since_last_request < self._min_request_interval:
                time.sleep(self._min_request_interval - time_since_last_request)
            
            # Try to fetch real data
            location = self._fetch_from_ipapi(ip)
            self._last_request_time = time.time()
            
            # Fallback to simulated if API fails
            if location is None:
                location = self._generate_simulated_location(ip)
                location['fallback'] = True
        
        # Cache the result
        if len(self._cache) >= self._cache_size:
            # Remove oldest entry
            self._cache.pop(next(iter(self._cache)))
        self._cache[ip] = location
        
        return location


class ApplicationTracker:
    """Track which applications/services are being targeted by network traffic.
    
    Identifies applications by port number and protocol, tracks attack patterns,
    and maintains statistics about which services are under attack.
    """
    
    # Comprehensive port-to-application mapping
    PORT_APPLICATIONS = {
        # Web Services
        80: ("HTTP Server", "Web", "🌐", "Web server - unencrypted"),
        443: ("HTTPS Server", "Web", "🔒", "Secure web server"),
        8080: ("HTTP Proxy", "Web", "🌐", "Alternative HTTP port/proxy"),
        8443: ("HTTPS Alt", "Web", "🔒", "Alternative HTTPS port"),
        8000: ("HTTP Dev Server", "Web", "🌐", "Development web server"),
        3000: ("Node.js/React", "Web", "⚙️", "Node.js or React development"),
        4200: ("Angular Dev", "Web", "🅰️", "Angular development server"),
        5000: ("Flask/Python", "Web", "🐍", "Flask or Python web app"),
        8081: ("HTTP Alt", "Web", "🌐", "Alternative HTTP port"),
        
        # Email Services
        25: ("SMTP", "Email", "📧", "Email delivery (unencrypted)"),
        110: ("POP3", "Email", "📧", "Email retrieval (unencrypted)"),
        143: ("IMAP", "Email", "📧", "Email access (unencrypted)"),
        465: ("SMTPS", "Email", "📧", "Secure SMTP"),
        587: ("SMTP Submission", "Email", "📧", "Email submission port"),
        993: ("IMAPS", "Email", "📧", "Secure IMAP"),
        995: ("POP3S", "Email", "📧", "Secure POP3"),
        
        # File Transfer
        20: ("FTP Data", "File Transfer", "📁", "FTP data channel"),
        21: ("FTP Control", "File Transfer", "📁", "FTP control channel"),
        22: ("SSH/SFTP", "Secure Shell", "🔐", "Secure shell and file transfer"),
        69: ("TFTP", "File Transfer", "📁", "Trivial file transfer"),
        115: ("SFTP", "File Transfer", "📁", "Simple file transfer"),
        989: ("FTPS Data", "File Transfer", "📁", "Secure FTP data"),
        990: ("FTPS Control", "File Transfer", "📁", "Secure FTP control"),
        
        # Databases
        1433: ("MS SQL Server", "Database", "🗄️", "Microsoft SQL Server"),
        1521: ("Oracle DB", "Database", "🗄️", "Oracle database"),
        3306: ("MySQL", "Database", "🗄️", "MySQL/MariaDB database"),
        5432: ("PostgreSQL", "Database", "🗄️", "PostgreSQL database"),
        5984: ("CouchDB", "Database", "🗄️", "CouchDB NoSQL database"),
        6379: ("Redis", "Database", "🗄️", "Redis in-memory database"),
        7474: ("Neo4j", "Database", "🗄️", "Neo4j graph database"),
        8529: ("ArangoDB", "Database", "🗄️", "ArangoDB multi-model database"),
        9200: ("Elasticsearch", "Database", "🗄️", "Elasticsearch search engine"),
        27017: ("MongoDB", "Database", "🗄️", "MongoDB NoSQL database"),
        28015: ("RethinkDB", "Database", "🗄️", "RethinkDB database"),
        
        # Remote Access
        23: ("Telnet", "Remote Access", "💻", "Unencrypted remote access"),
        3389: ("RDP", "Remote Desktop", "🖥️", "Windows Remote Desktop"),
        5900: ("VNC", "Remote Desktop", "🖥️", "VNC remote desktop"),
        5901: ("VNC Alt", "Remote Desktop", "🖥️", "Alternative VNC port"),
        
        # Network Services
        53: ("DNS", "Network", "🌍", "Domain Name System"),
        67: ("DHCP Server", "Network", "🌍", "DHCP server"),
        68: ("DHCP Client", "Network", "🌍", "DHCP client"),
        123: ("NTP", "Time Sync", "🕐", "Network time protocol"),
        161: ("SNMP", "Monitoring", "📊", "Simple Network Management"),
        162: ("SNMP Trap", "Monitoring", "📊", "SNMP notifications"),
        389: ("LDAP", "Directory", "📂", "Lightweight Directory Access"),
        636: ("LDAPS", "Directory", "📂", "Secure LDAP"),
        
        # Messaging & Queue
        1883: ("MQTT", "IoT Messaging", "📡", "IoT message broker"),
        5222: ("XMPP", "Messaging", "💬", "Instant messaging protocol"),
        5672: ("AMQP", "Messaging", "💬", "Advanced message queuing"),
        6667: ("IRC", "Chat", "💬", "Internet Relay Chat"),
        
        # Gaming & Media
        25565: ("Minecraft", "Gaming", "🎮", "Minecraft game server"),
        27015: ("Source Engine", "Gaming", "🎮", "Source engine games"),
        554: ("RTSP", "Media Streaming", "📹", "Real-time streaming"),
        1935: ("RTMP", "Media Streaming", "📹", "Adobe Flash media"),
        
        # VPN & Security
        500: ("IKE/IPSec", "VPN", "🔒", "IPSec key exchange"),
        1194: ("OpenVPN", "VPN", "🔒", "OpenVPN server"),
        1723: ("PPTP", "VPN", "🔒", "Point-to-Point Tunneling"),
        4500: ("IPSec NAT-T", "VPN", "🔒", "IPSec NAT traversal"),
        
        # Container & Cloud
        2375: ("Docker API", "Container", "🐳", "Docker API (insecure)"),
        2376: ("Docker TLS", "Container", "🐳", "Docker API (secure)"),
        2377: ("Docker Swarm", "Container", "🐳", "Docker Swarm cluster"),
        6443: ("Kubernetes API", "Container", "☸️", "Kubernetes API server"),
        8001: ("Kubernetes Proxy", "Container", "☸️", "Kubernetes proxy"),
        10250: ("Kubelet", "Container", "☸️", "Kubernetes kubelet"),
        
        # Monitoring & Metrics
        9090: ("Prometheus", "Monitoring", "📊", "Prometheus metrics"),
        9093: ("Alertmanager", "Monitoring", "📊", "Prometheus alerts"),
        3000: ("Grafana", "Monitoring", "📊", "Grafana dashboards"),
        4000: ("Chronograf", "Monitoring", "📊", "InfluxDB UI"),
        8086: ("InfluxDB", "Database", "📊", "InfluxDB time-series database"),
        
        # Additional Common Services
        111: ("RPCBind", "Network", "🔧", "RPC portmapper"),
        135: ("MS RPC", "Network", "🔧", "Microsoft RPC"),
        137: ("NetBIOS-NS", "Network", "🔧", "NetBIOS name service"),
        138: ("NetBIOS-DGM", "Network", "🔧", "NetBIOS datagram"),
        139: ("NetBIOS-SSN", "Network", "🔧", "NetBIOS session"),
        445: ("SMB", "File Sharing", "📁", "Windows file sharing"),
        514: ("Syslog", "Logging", "📝", "System logging"),
        631: ("IPP", "Printing", "🖨️", "Internet Printing Protocol"),
        873: ("Rsync", "File Sync", "🔄", "Remote file synchronization"),
        1080: ("SOCKS Proxy", "Proxy", "🔀", "SOCKS proxy server"),
        3128: ("Squid Proxy", "Proxy", "🔀", "Squid web proxy"),
        8888: ("HTTP Alt", "Web", "🌐", "Alternative HTTP port"),
    }
    
    def __init__(self):
        """Initialize the application tracker."""
        from collections import defaultdict
        
        self.attack_targets = defaultdict(int)  # Application -> attack count
        self.source_countries = defaultdict(int)  # Country -> attack count
        self.service_attacks = defaultdict(lambda: defaultdict(int))  # Service -> Country -> count
        self.port_stats = defaultdict(int)  # Port -> attack count
        self.protocol_stats = defaultdict(int)  # Protocol -> attack count
        
    def track_packet(
        self, 
        src_ip: str, 
        dst_ip: str, 
        dst_port: int, 
        protocol: str,
        is_attack: bool,
        attack_type: str = None,
        geocoder: Optional[IPGeocoder] = None,
        use_simulation: bool = True
    ) -> Dict:
        """Track a packet and identify target application.
        
        Parameters
        ----------
        src_ip : str
            Source IP address.
        dst_ip : str
            Destination IP address.
        dst_port : int
            Destination port number.
        protocol : str
            Protocol (tcp, udp, icmp).
        is_attack : bool
            Whether this packet is classified as an attack.
        attack_type : str, optional
            Type of attack if is_attack is True.
        geocoder : IPGeocoder, optional
            Geocoder instance to use. Creates new one if not provided.
        use_simulation : bool
            Whether to use simulated geolocation data.
        
        Returns
        -------
        dict
            Information about the targeted application and source location.
        """
        # Create geocoder if not provided
        if geocoder is None:
            geocoder = IPGeocoder()
        
        # Identify target application
        app_info = self.identify_application(dst_port, protocol)
        
        # Get source location
        geo_info = geocoder.geocode(src_ip, use_simulation=use_simulation)
        
        # Track statistics if it's an attack
        if is_attack:
            app_name = app_info["application"]
            country = geo_info["country"]
            
            self.attack_targets[app_name] += 1
            self.source_countries[country] += 1
            self.service_attacks[app_name][country] += 1
            self.port_stats[dst_port] += 1
            self.protocol_stats[protocol.lower()] += 1
        
        return {
            "application": app_info,
            "source_location": geo_info,
            "destination_ip": dst_ip,
            "source_ip": src_ip,
            "is_targeted_attack": is_attack,
            "attack_type": attack_type
        }
    
    def identify_application(self, port: int, protocol: str) -> Dict:
        """Identify application/service from port and protocol.
        
        Parameters
        ----------
        port : int
            Port number.
        protocol : str
            Protocol (tcp, udp, icmp).
        
        Returns
        -------
        dict
            Application name, category, icon, and description.
        """
        if port in self.PORT_APPLICATIONS:
            name, category, icon, description = self.PORT_APPLICATIONS[port]
            return {
                "application": name,
                "category": category,
                "icon": icon,
                "port": port,
                "protocol": protocol.upper(),
                "description": description,
                "full_description": f"{name} on port {port}/{protocol} - {description}"
            }
        else:
            # Unknown port - try to categorize by range
            if port < 1024:
                category = "System Service"
                icon = "⚙️"
                desc = "Well-known system service port"
            elif 1024 <= port < 49152:
                category = "User Application"
                icon = "📱"
                desc = "Registered user application port"
            else:
                category = "Dynamic/Private"
                icon = "🔧"
                desc = "Dynamic or private port"
            
            return {
                "application": f"Unknown Service",
                "category": category,
                "icon": icon,
                "port": port,
                "protocol": protocol.upper(),
                "description": f"Unknown service on port {port}",
                "full_description": f"Unknown service on port {port}/{protocol} - {desc}"
            }
    
    def get_top_targets(self, n: int = 10) -> list:
        """Get the most attacked applications.
        
        Parameters
        ----------
        n : int
            Number of top targets to return.
            
        Returns
        -------
        list
            List of (application, count) tuples sorted by attack count.
        """
        return sorted(
            self.attack_targets.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:n]
    
    def get_top_source_countries(self, n: int = 10) -> list:
        """Get countries with most attack sources.
        
        Parameters
        ----------
        n : int
            Number of countries to return.
            
        Returns
        -------
        list
            List of (country, count) tuples sorted by attack count.
        """
        return sorted(
            self.source_countries.items(),
            key=lambda x: x[1],
            reverse=True
        )[:n]
    
    def get_top_ports(self, n: int = 10) -> list:
        """Get most attacked ports.
        
        Parameters
        ----------
        n : int
            Number of ports to return.
            
        Returns
        -------
        list
            List of (port, count) tuples sorted by attack count.
        """
        return sorted(
            self.port_stats.items(),
            key=lambda x: x[1],
            reverse=True
        )[:n]
    
    def get_protocol_distribution(self) -> dict:
        """Get attack distribution by protocol.
        
        Returns
        -------
        dict
            Protocol -> count mapping.
        """
        return dict(self.protocol_stats)
    
    def get_service_attack_matrix(self) -> Dict:
        """Get service-to-country attack matrix.
        
        Returns
        -------
        dict
            Nested dict of service -> country -> count.
        """
        return dict(self.service_attacks)
    
    def get_statistics_summary(self) -> dict:
        """Get complete statistics summary.
        
        Returns
        -------
        dict
            Complete statistics including top targets, sources, ports, etc.
        """
        total_attacks = sum(self.attack_targets.values())
        
        return {
            "total_attacks": total_attacks,
            "unique_targets": len(self.attack_targets),
            "unique_sources": len(self.source_countries),
            "unique_ports": len(self.port_stats),
            "top_targets": self.get_top_targets(5),
            "top_sources": self.get_top_source_countries(5),
            "top_ports": self.get_top_ports(5),
            "protocol_distribution": self.get_protocol_distribution()
        }
    
    def clear_statistics(self):
        """Clear all tracking statistics."""
        self.attack_targets.clear()
        self.source_countries.clear()
        self.service_attacks.clear()
        self.port_stats.clear()
        self.protocol_stats.clear()
    
    def get_location_summary(self, ip: str, use_simulation: bool = False) -> str:
        """Get a human-readable location summary.
        
        Parameters
        ----------
        ip : str
            IP address to geocode.
        use_simulation : bool
            Use simulated data instead of real API calls.
        
        Returns
        -------
        str
            Formatted location string (e.g., "Beijing, China").
        """
        location = self.geocode(ip, use_simulation)
        
        if location.get('private'):
            return "Local Network"
        
        city = location.get('city', 'Unknown')
        country = location.get('country', 'Unknown')
        
        if city != 'Unknown' and country != 'Unknown':
            return f"{city}, {country}"
        elif country != 'Unknown':
            return country
        else:
            return "Unknown Location"
    
    def clear_cache(self):
        """Clear the geocoding cache."""
        self._cache.clear()


# Global geocoder instance
_geocoder = IPGeocoder()


def geocode_ip(ip: str, use_simulation: bool = False) -> dict:
    """Convenience function to geocode an IP address.
    
    Parameters
    ----------
    ip : str
        IP address to geocode.
    use_simulation : bool
        Use simulated data instead of real API calls.
    
    Returns
    -------
    dict
        Location information.
    """
    return _geocoder.geocode(ip, use_simulation)


def get_location_summary(ip: str, use_simulation: bool = False) -> str:
    """Get a human-readable location summary for an IP.
    
    Parameters
    ----------
    ip : str
        IP address to geocode.
    use_simulation : bool
        Use simulated data instead of real API calls.
    
    Returns
    -------
    str
        Formatted location string.
    """
    return _geocoder.get_location_summary(ip, use_simulation)


if __name__ == "__main__":
    # Test the geocoder
    print("IP Geolocation Test\n" + "="*50)
    
    # Test with simulated IPs
    test_ips = [
        "192.168.1.1",      # Private IP
        "8.8.8.8",          # Google DNS
        "1.1.1.1",          # Cloudflare DNS
        "45.33.32.156",     # Random public IP
        "103.21.244.0",     # Random public IP
    ]
    
    print("\nUsing simulation mode (for testing):\n")
    for ip in test_ips:
        location = geocode_ip(ip, use_simulation=True)
        summary = get_location_summary(ip, use_simulation=True)
        print(f"{ip:15} → {summary}")
        print(f"  Coordinates: {location['latitude']:.4f}, {location['longitude']:.4f}")
        print(f"  ISP: {location['isp']}")
        print()
    
    print("="*50)
    print("Geolocation module ready!")
