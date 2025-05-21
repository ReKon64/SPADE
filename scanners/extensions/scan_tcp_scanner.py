# File: scanners/tcp_scanner.py
from core.imports import *
from core.logging import run_and_log
from scanners.scanner import Scanner

@Scanner.extend
def scan_tcp_scan(self):
    """
    Perform a TCP network scan using nmap.
    Currently parser appends the CMD
    Returns:
        str: Path to XML output file
    """
    # Create temporary file for XML output
    with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as tmp_file:
        xml_output_path = tmp_file.name
    
    try:
        # Build and execute nmap command for TCP scan
        cmd = f"nmap {self.options['target']} {self.options.get('tcp_options') or '-A -T4 -p-'} -vv --reason -Pn -n -oX {xml_output_path}"

        logging.info(f"Executing TCP nmap command: {cmd}")

        # Use real time logging if enabled in options
        realtime = self.options.get("realtime", False)
        run_and_log(cmd, very_verbose=realtime)
        
        # Store the output path in the options for later processing
        self.options['tcp_output_path'] = xml_output_path
        logging.info(f"TCP scan completed. Results saved to {xml_output_path}")
        
        return xml_output_path
        
    except subprocess.CalledProcessError as e:
        logging.error(f"TCP Nmap scan failed: {e}")
        logging.error(f"Stderr: {e.stderr}")
        # Still return the path in case partial results were generated
        self.options['tcp_output_path'] = xml_output_path
        return xml_output_path
    except Exception as e:
        logging.error(f"Error during TCP nmap scan: {e}")
        self.options['tcp_output_path'] = xml_output_path
        return xml_output_path
