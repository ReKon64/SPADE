# File: scanners/tcp_scanner.py
from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def scan_tcp_scan(self):
    """
    Perform a TCP network scan using nmap.
    
    Returns:
        str: Path to XML output file
    """
    # Create temporary file for XML output
    with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as tmp_file:
        xml_output_path = tmp_file.name
    
    try:
        # Build and execute nmap command for TCP scan
        #cmd = f"nmap {self.options['target']} {self.options['tcp_ports']} {self.options.get('tcp_options') or '-A -T4'} -vv --reason -Pn -n -oX {xml_output_path}"
        cmd = f"nmap {self.options['target']} --top-ports=1000 {self.options.get('tcp_options') or '-A -T4'} -vv --reason -Pn -n -oX {xml_output_path}"

        logging.info(f"Executing TCP nmap command: {cmd}")
        
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True, 
            check=True
        )
        
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
