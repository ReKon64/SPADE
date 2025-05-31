# File: scanners/tcp_scanner.py
from core.imports import *
from core.logging import run_and_log
from scanners.scanner import Scanner

@Scanner.extend
def scan_tcp_scan(self, plugin_results=None):
    """
    Perform a TCP network scan using nmap.
    Returns:
        dict: { "cmd": ..., "results": ... }
    """
    if plugin_results is None:
        plugin_results = {}

    # Create temporary file for XML output
    with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as tmp_file:
        xml_output_path = tmp_file.name

    try:
        # Build and execute nmap command for TCP scan
        cmd = f"nmap {self.options['target']} {self.options.get('tcp_options') or '-A -T4 -p-'} -vv --reason -Pn -n -oX {xml_output_path}"
        logging.info(f"Executing TCP nmap command: {cmd}")

        # Use real time logging if enabled in options
        realtime = self.options.get("realtime", False)
        run_and_log(cmd, very_verbose=realtime, prefix="[NMAP_TCP]")

        # Store the output path in the options for later processing
        self.options['tcp_output_path'] = xml_output_path
        logging.info(f"TCP scan completed. Results saved to {xml_output_path}")

        return {"cmd": cmd, "results": {"xml_output_path": xml_output_path}}
    except subprocess.CalledProcessError as e:
        logging.error(f"TCP Nmap scan failed: {e}")
        logging.error(f"Stderr: {e.stderr}")
        self.options['tcp_output_path'] = xml_output_path
        return {"cmd": cmd, "results": {"error": str(e), "xml_output_path": xml_output_path}}
    except Exception as e:
        logging.error(f"Error during TCP nmap scan: {e}")
        self.options['tcp_output_path'] = xml_output_path
        return {"cmd": cmd, "results": {"error": str(e), "xml_output_path": xml_output_path}}
