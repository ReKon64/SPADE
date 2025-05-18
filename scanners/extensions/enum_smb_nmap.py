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
    cmd = f"nmap -p {port} {script_arg} -Pn -n -oX {xml_output_path} {host}"

    #very_verbose = getattr(self.options, "very_verbose", False) or self.options.get("very_verbose", False)
    try:
        logging.info(f"Executing SMB Nmap scripts: {cmd}")
        run_and_log(cmd, very_verbose=verbosity)
        with open(xml_output_path, "r") as f:
            xml_data = f.read()
        parsed = _parse_smb_nmap_xml(xml_data)
    except Exception as e:
        logging.error(f"Error during SMB Nmap scripts: {e}")
        parsed = {"error": str(e)}
    finally:
        try:
            os.remove(xml_output_path)
            logging.info(f"Deleted temporary file: {xml_output_path}")
        except Exception as e:
            logging.error(f"Failed to delete file {xml_output_path}: {e}")

    return parsed

def _parse_smb_nmap_xml(xml_data):
    """
    Parse for SMB Nmap XML output, extracting script results.
    """
    results = {}
    try:
        root = ET.fromstring(xml_data)
        for host in root.findall('.//host'):
            for port in host.findall('.//port'):
                portid = port.get('portid')
                protocol = port.get('protocol')
                if portid and protocol:
                    port_key = f"{protocol}/{portid}"
                    results[port_key] = {}
                    for script in port.findall('./script'):
                        script_id = script.get('id')
                        output = script.get('output')
                        if script_id:
                            results[port_key][script_id] = output
    except Exception as e:
        results["parse_error"] = str(e)
    return results