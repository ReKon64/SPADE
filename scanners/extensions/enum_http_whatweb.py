# File: scanners/enum_http_whatweb.py
from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def enum_http_whatweb(self):
    with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmp_file:
        output_path = tmp_file.name
    
    try:
        # Build and execute nmap command for TCP scan
        # make it fetch the ports itself
        # Also it will append itself?
        cmd = f"whatweb {self.options['target']}:{self.options['port_id']} -p -a 4 -v --log-json={output_path}"
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