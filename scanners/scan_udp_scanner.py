# File: scanners/udp_scanner.py
from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def scan_udp_scan(self):
    """
    Perform a UDP network scan using nmap.
    
    Returns:
        str: Path to XML output file
    """
    # Create temporary file for XML output
    with tempfile.NamedTemporaryFile(delete=False, suffix='.xml') as tmp_file:
        xml_output_path = tmp_file.name
    
    try:
        # Build and execute nmap command for UDP scan - note the -sU flag for UDP
        cmd = f"nmap {self.options['target']} {self.options.get('udp_options', '-sUCV --top-ports 100')} -oX {xml_output_path}"
        logging.info(f"Executing UDP nmap command: {cmd}")
        
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True, 
            check=True
        )
        
        # Store the output path in the options for later processing
        self.options['udp_output_path'] = xml_output_path
        logging.info(f"UDP scan completed. Results saved to {xml_output_path}")
        
        return xml_output_path
        
    except subprocess.CalledProcessError as e:
        logging.error(f"UDP Nmap scan failed: {e}")
        logging.error(f"Stderr: {e.stderr}")
        # Still return the path in case partial results were generated
        self.options['udp_output_path'] = xml_output_path
        return xml_output_path
    except Exception as e:
        logging.error(f"Error during UDP nmap scan: {e}")
        self.options['udp_output_path'] = xml_output_path
        return xml_output_path
