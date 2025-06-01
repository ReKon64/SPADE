# # File: scanners/udp_scanner.py
from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def scan_udp_scan(self, plugin_results=None):
    """
    Perform a UDP network scan using nmap.
    Returns:
        dict: { "cmd": ..., "results": ... }
    """
    if plugin_results is None:
        plugin_results = {}

    # Create temporary file for XML output
    with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as tmp_file:
        xml_output_path = tmp_file.name

    try:
        # Build and execute nmap command for UDP scan
        #         cmd = f"nmap {self.options['target']} {self.options.get('tcp_options') or '-A -T4 -p-'} -vv --reason -Pn -n -oX {xml_output_path}"

        cmd = f"nmap {self.options['target']} {self.options['udp_ports']} -sU {self.options.get('udp_options') or '-sCV -T4'} -vv --reason -Pn -n -oX {xml_output_path}"
        logging.info(f"Executing UDP nmap command: {cmd}")

        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            check=True
        )

        self.options['udp_output_path'] = xml_output_path
        logging.info(f"UDP scan completed. Results saved to {xml_output_path}")

        return {"cmd": cmd, "results": {"xml_output_path": xml_output_path}}
    except subprocess.CalledProcessError as e:
        logging.error(f"UDP Nmap scan failed: {e}")
        logging.error(f"Stderr: {e.stderr}")
        self.options['udp_output_path'] = xml_output_path
        return {"cmd": cmd, "results": {"error": str(e), "xml_output_path": xml_output_path}}
    except Exception as e:
        logging.error(f"Error during UDP nmap scan: {e}")
        self.options['udp_output_path'] = xml_output_path
        return {"cmd": cmd, "results": {"error": str(e), "xml_output_path": xml_output_path}}
