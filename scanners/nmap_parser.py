# File: scanners/nmap_parser.py
from core.imports import *

def parse_nmap_xml(xml_data: str):
    """
    Parse nmap XML output and extract structured findings.
    
    Args:
        xml_data: XML output from nmap
        
    Returns:
        dict: Structured scan results
    """
    findings = []
    structured_results = {
        'hosts': [],
        'raw_xml': xml_data
    }
    
    try:
        root = ET.fromstring(xml_data)
        
        # Process each host
        for host in root.findall('.//host'):
            host_data = {'ports': []}
            
            # Get host address
            addr_elem = host.find('./address[@addrtype="ipv4"]')
            if addr_elem is None:
                continue
                
            ip_address = addr_elem.get('addr')
            host_data['ip'] = ip_address
            
            # Find hostname if available
            hostname = "unknown"
            hostname_elem = host.find('./hostnames/hostname')
            if hostname_elem is not None:
                hostname = hostname_elem.get('name', 'unknown')
            host_data['hostname'] = hostname
            
            # Process ports
            for port in host.findall('.//port'):
                port_data = {}
                port_id = port.get('portid')
                protocol = port.get('protocol')
                port_data['id'] = port_id
                port_data['protocol'] = protocol
                
                # Get state
                state_elem = port.find('./state')
                if state_elem is None:
                    continue
                    
                state = state_elem.get('state')
                port_data['state'] = state
                
                # Get service info if available
                service_name = "unknown"
                service_elem = port.find('./service')
                if service_elem is not None:
                    service_name = service_elem.get('name', 'unknown')
                    product = service_elem.get('product', '')
                    version = service_elem.get('version', '')
                    port_data['service'] = {
                        'name': service_name,
                        'product': product,
                        'version': version
                    }
                    
                    if product and version:
                        service_display = f"{service_name} ({product} {version})"
                    elif product:
                        service_display = f"{service_name} ({product})"
                    else:
                        service_display = service_name
                else:
                    service_display = "unknown"
                    port_data['service'] = {'name': 'unknown'}
                
                # Add port to host data
                host_data['ports'].append(port_data)
                
                # Generate findings for open ports
                if state == 'open':
                    finding = f"Host {ip_address} ({hostname}) has open {protocol} port {port_id} ({service_display})"
                    findings.append({
                        'type': 'info',
                        'message': finding
                    })
                    
                    # Add security findings based on service
                    if service_name.startswith('http') and port_id not in ['80', '443']:
                        findings.append({
                            'type': 'warning',
                            'message': f"Non-standard HTTP port {port_id} on {ip_address}"
                        })
                    
                    if service_name.startswith('telnet'):
                        findings.append({
                            'type': 'critical',
                            'message': f"Insecure Telnet service running on {ip_address}:{port_id}"
                        })
                        
                    if service_name.startswith('ftp') and not service_name.lower().find('sftp'):
                        findings.append({
                            'type': 'high',
                            'message': f"Insecure FTP service on {ip_address}:{port_id}"
                        })
            
            # Add host to results
            structured_results['hosts'].append(host_data)
    
    except ET.ParseError as e:
        logging.error(f"Error parsing nmap XML output: {e}")
        findings.append({
            'type': 'error',
            'message': f"Failed to parse scan results: {e}"
        })
    except Exception as e:
        logging.error(f"Error processing nmap findings: {e}")
        findings.append({
            'type': 'error',
            'message': f"Error processing scan results: {e}"
        })
        
    structured_results['findings'] = findings
    return structured_results
