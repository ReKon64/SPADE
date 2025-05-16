from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def enum_smb_nmap(self):
    """
    Run Nmap SMB scripts against the target host/port.
    Returns:
        dict: Parsed results of SMB Nmap scripts
    """
    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]

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
    cmd = (
        f"nmap -p {port} {script_arg} -Pn -n -oX {xml_output_path} {host}"
    )

    try:
        logging.info(f"Executing SMB Nmap scripts: {cmd}")
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            check=True
        )
        # Parse the XML output into a dict
        with open(xml_output_path, "r") as f:
            xml_data = f.read()
        parsed = _parse_smb_nmap_xml(xml_data)
    except subprocess.CalledProcessError as e:
        logging.error(f"SMB Nmap scripts failed: {e}")
        logging.error(f"Stderr: {e.stderr}")
        parsed = {"error": str(e), "stderr": e.stderr}
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