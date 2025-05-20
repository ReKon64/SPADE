# File: scanners/nmap_parser.py
from core.imports import *

def _extract_rdp_ntlm_info(host_elem):
    """
    Helper to extract RDP NTLM info (domain and computername) from a host element.
    Returns a dict with 'domain' and 'computername' if found, else empty dict.
    Matches if:
      - protocol is tcp
      - and (portid is 3389 OR service name is ms-wbt-server OR product contains "Microsoft Terminal Services")
    """
    for port in host_elem.findall('.//port'):
        port_id = port.get('portid')
        protocol = port.get('protocol')
        service_elem = port.find('./service')
        service_name = service_elem.get('name', '').lower() if service_elem is not None else ''
        product = service_elem.get('product', '').lower() if service_elem is not None else ''
        if (
            protocol == "tcp" and (
                port_id == "3389" or
                service_name == "ms-wbt-server" or
                "microsoft terminal services" in product
            )
        ):
            for script_elem in port.findall('./script'):
                if script_elem.get('id') == "rdp-ntlm-info":
                    info = {}
                    for elem in script_elem.findall('./elem'):
                        key = elem.get('key')
                        value = elem.text
                        if key == "DNS_Tree_Name":
                            info["domain"] = value
                        if key == "DNS_Computer_Name":
                            info["computername"] = value
                    return info
    return {}

def _extract_ldap_info(host_elem):
    """
    Helper to extract extrainfo fields from LDAP ports and return as a dict.
    Looks for ports with service name 'ldap' and collects their extrainfo fields.
    Returns a dict {portid: extrainfo, ...} or an empty dict if none found.
    """
    ldap_info = {}
    for port in host_elem.findall('.//port'):
        service_elem = port.find('./service')
        if service_elem is not None:
            service_name = service_elem.get('name', '').lower()
            extrainfo = service_elem.get('extrainfo', '')
            portid = port.get('portid')
            if service_name == "ldap" and extrainfo:
                ldap_info[portid] = extrainfo
    return ldap_info

def parse_nmap_xml(xml_data: str):
    logging.debug(f"[Parse_NMAP_XML] Data : {xml_data}")
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

        # Extract the nmap command from the <nmaprun> element's 'args' attribute
        nmap_command = None
        nmaprun_elem = root.find('.')
        if nmaprun_elem is not None:
            nmap_command = nmaprun_elem.get('args')
        
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
            
            # Extract RDP NTLM info (domain/computername) if present
            rdp_info = _extract_rdp_ntlm_info(host)
            domain = rdp_info.get("domain")
            computername = rdp_info.get("computername")

            # Initialize host_data with desired key order
            host_data = {
                'ip': ip_address,
                'hostname': hostname,
            }
            if nmap_command:
                host_data["nmap_command"] = nmap_command
            if domain:
                host_data["domain"] = domain
            if computername:
                host_data["computername"] = computername
            host_data["ports"] = []

            # Add extrainfo if present at the host level
            extrainfo_elem = host.find('./extrainfo')
            if extrainfo_elem is not None and extrainfo_elem.text:
                host_data["extrainfo"] = extrainfo_elem.text

            # Extract LDAP extrainfo if present
            ldap_info = _extract_ldap_info(host)
            if ldap_info:
                host_data["ldap_info"] = ldap_info

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
                extrainfo = ""
                if service_elem is not None:
                    extrainfo = service_elem.get('extrainfo', '')
                if extrainfo:
                    port_data['extrainfo'] = extrainfo

                if service_elem is not None:
                    service_name = service_elem.get('name', 'unknown')
                    product = service_elem.get('product', '')
                    version = service_elem.get('version', '')
                    tunnel = service_elem.get('tunnel', '')
                    port_data['service'] = {
                        'name': service_name,
                        'product': product,
                        'version': version,
                        'tunnel': tunnel,
                    }

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

                    if not script_data and script_elem.get('output'):
                        scripts[script_id] = script_elem.get('output')
                    else:
                        scripts[script_id] = script_data

                if scripts:
                    port_data['scripts'] = scripts

                # Add port to host data
                host_data['ports'].append(port_data)

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
