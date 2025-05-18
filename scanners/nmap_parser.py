# File: scanners/nmap_parser.py
from core.imports import *

def parse_nmap_xml(xml_data: str):
    logging.debug("[!] parse_nmap_xml called")
    """
    Parse nmap XML output and extract structured findings.
    
    Args:
        xml_data: XML output from nmap
        
    Returns:
        dict: Structured scan results
    """
    errors = []
    structured_results = {
        'hosts': [],
        'raw_xml': xml_data
    }
    
    try:
        root = ET.fromstring(xml_data)
        
        # Process each host
        for host in root.findall('.//host'):
            # Get host address
            addr_elem = host.find('./address[@addrtype="ipv4"]')
            if addr_elem is None:
                continue
                
            ip_address = addr_elem.get('addr')

            # Find hostname if available
            hostname = "unknown"
            hostname_elem = host.find('./hostnames/hostname')
            if hostname_elem is not None:
                hostname = hostname_elem.get('name', 'unknown')
            
            # Initialize host_data with desired key order
            host_data = {
                'ip': ip_address,
                'hostname': hostname,
                'ports': []
            }

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
                    tunnel = service_elem.get('tunnel', '')
                    #extrainfo = service_elem.get('extrainfo', '')
                    port_data['service'] = {
                        'name': service_name,
                        'product': product,
                        'version': version,
                        'tunnel': tunnel,
                        #'extrainfo': extrainfo, 
                    }

                # Add port to host data
                host_data['ports'].append(port_data)
                # Parse all script outputs
            scripts = {}
            for script_elem in port.findall('./script'):
                script_id = script_elem.get('id')
                if not script_id:
                    continue

                script_data = {}
                for elem in script_elem.findall('./elem'):
                    key = elem.get('key')
                    value = elem.text
                    if key and value:
                        script_data[key] = value

                # If no structured elements, fall back to raw script output
                if not script_data and script_elem.get('output'):
                    scripts[script_id] = script_elem.get('output')
                else:
                    scripts[script_id] = script_data

            if scripts:
                port_data['scripts'] = scripts

            # Add host to results
            structured_results['hosts'].append(host_data)
    
    except ET.ParseError as e:
        logging.error(f"Error parsing nmap XML output: {e}")
        structured_results.append({
            'type': 'error',
            'message': f"Failed to parse scan results: {e}"
        })
    except Exception as e:
        logging.error(f"Error processing nmap findings: {e}")
        structured_results.append({
            'type': 'error',
            'message': f"Error processing scan results: {e}"
        })
        
    structured_results['Errors'] = errors
    return structured_results
