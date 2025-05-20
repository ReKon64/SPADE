from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def enum_curl_confirmation(self):
    """
    Use curl to check if an HTTP port is a real web service or a default Windows/IIS/empty response.
    Returns:
        dict: Contains HTTP status code, headers, and a snippet of the body.
    """
    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]
    port_obj = self.options["current_port"].get("port_obj", {})
    service = port_obj.get("service", {}) if port_obj else {}
    tunnel = service.get("tunnel", "")
    protocol = "https" if tunnel else "http"
    verbosity = self.options.get("realtime", False)
    results = {}

    url = f"{protocol}://{host}:{port}/"
    cmd = f"curl -i --insecure --max-time 15 {url}"

    try:
        logging.info(f"Executing: {cmd}")
        if verbosity:
            from core.logging import run_and_log
            output = run_and_log(cmd, very_verbose=True)
        else:
            output = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=15
            ).stdout

        # Parse HTTP status and headers
        lines = output.splitlines()
        status_line = next((line for line in lines if line.startswith("HTTP/")), "")
        headers = {}
        body = []
        in_headers = True
        for line in lines[1:]:
            if in_headers and line == "":
                in_headers = False
                continue
            if in_headers:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()
            else:
                body.append(line)
        results["status_line"] = status_line
        results["headers"] = headers
        results["body_snippet"] = "\n".join(body[:10])  # First 10 lines of body

    except Exception as e:
        results["error"] = str(e)

    return results