# File: scanners/tcp_scanner.py
from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def tcp_scan(self):
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
        cmd = f"nmap {self.options.get('target')} {self.options.get('tcp_options', '-A -T3')} -oX {xml_output_path}"
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
