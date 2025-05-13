# File: scanners/enum_http_whatweb.py
from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def scan_http_whatweb(self):
    with tempfile.NamedTemporaryFile(delete=False, suffix='.whatweb') as tmp_file:
        output_path = tmp_file.name
    
    try:
        # Build and execute nmap command for TCP scan
        cmd = f"whatweb {self.options['target']} -a 3 -v --log-xml={output_path}"
        logging.info(f"Executing TCP nmap command: {cmd}")
        
        result = subprocess.run(
            cmd, 
            shell=True, 
            capture_output=True, 
            text=True, 
            check=True
        )
        
        # Store the output path in the options for later processing
        self.options['whatweb_output_path'] = output_path
        logging.info(f"Whatweb scan completed. Results saved to {output_path}")
        
        return output_path
        
    except subprocess.CalledProcessError as e:
        logging.error(f"Whatweb scan failed: {e}")
        logging.error(f"Stderr: {e.stderr}")
        # Still return the path in case partial results were generated
        self.options['whatweb_output_path'] = output_path
        return output_path
    except Exception as e:
        logging.error(f"Error during Whatweb scan: {e}")
        self.options['whatweb_output_path'] = output_path
        return output_path