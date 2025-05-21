from core.imports import *
from core.logging import *
from scanners.scanner import Scanner

@Scanner.extend
def enum_smb_nmap(self):
    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]
    verbosity = self.options["realtime"]

    with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as tmp_file:
        xml_output_path = tmp_file.name

    smb_scripts = [
        "smb-os-discovery",
        "smb-enum-shares",
        "smb-enum-users",
        "smb-enum-domains",
        "smb-enum-groups",
        "smb-security-mode",
        "smb2-security-mode",
        "smb2-time",
        "smb2-capabilities",
        "smb-protocols",
        "smb-vuln*"
    ]
    script_arg = "--script=" + ",".join(smb_scripts)
    cmd = f"nmap -p {port} {script_arg} -Pn -vv -n -oX {xml_output_path} {host}"

    try:
        logging.info(f"Executing SMB Nmap scripts: {cmd}")
        run_and_log(cmd, very_verbose=verbosity)
        with open(xml_output_path, "r") as f:
            xml_data = f.read()
        parsed = _parse_smb_nmap_xml(xml_data)
        logging.debug(f"[SMB_NMAP] Parsed Json : {parsed}")

    except Exception as e:
        logging.error(f"Error during SMB Nmap scripts: {e}")
        parsed = {"error": str(e)}
    finally:
        try:
            os.remove(xml_output_path)
            logging.info(f"Deleted temporary file: {xml_output_path}")
        except Exception as e:
            logging.error(f"Failed to delete file {xml_output_path}: {e}")

    return {"cmd": cmd, "results": parsed}

def _parse_smb_nmap_xml(xml_data):
    """
    Parse for SMB Nmap XML output, extracting script results.
    Handles both <port><script> and <hostscript><script> locations.
    """
    results = {}
    try:
        root = ET.fromstring(xml_data)
        for host in root.findall('.//host'):
            # Collect open ports
            open_ports = []
            for port in host.findall('.//port'):
                portid = port.get('portid')
                protocol = port.get('protocol')
                state = port.find('./state')
                if portid and protocol and state is not None and state.get('state') == 'open':
                    port_key = f"{protocol}/{portid}"
                    open_ports.append(port_key)
                    # (Optional) If you want to support <port><script> in the future:
                    port_scripts = {}
                    for script in port.findall('./script'):
                        script_id = script.get('id')
                        output = script.get('output')
                        if script_id:
                            port_scripts[script_id] = output
                    if port_scripts:
                        results[port_key] = port_scripts

            # Now handle <hostscript>
            hostscript = host.find('hostscript')
            if hostscript is not None:
                host_scripts = {}
                for script in hostscript.findall('script'):
                    script_id = script.get('id')
                    output = script.get('output')
                    if script_id:
                        host_scripts[script_id] = output
                # Attach hostscript results to all open ports
                for port_key in open_ports:
                    if port_key not in results:
                        results[port_key] = {}
                    results[port_key].update(host_scripts)
    except Exception as e:
        results["parse_error"] = str(e)
    return results