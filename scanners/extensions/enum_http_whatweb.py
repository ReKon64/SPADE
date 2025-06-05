# File: scanners/extensions/enum_http_whatweb.py
from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def enum_http_whatweb(self, plugin_results=None):
    """
    Run WhatWeb against the current host/port and return parsed results.
    Only runs if the port's plugins['enum_http_curl_confirmation']['isreal'] is True.
    Returns:
        dict: { "cmd": ..., "results": ... }
    """
    if plugin_results is None:
        plugin_results = {}

    port_obj = self.options["current_port"].get("port_obj", {})
    curl_result = plugin_results.get("enum_http_curl_confirmation", {})
    isreal = False
    if isinstance(curl_result, dict):
        if isinstance(curl_result.get("results"), dict):
            isreal = curl_result["results"].get("isreal") is True
    if not isreal:
        logging.debug(f"[enum_http_whatweb] Checked {curl_result} for isreal")
        return {"skipped": "Not a real HTTP(S) service (isreal != True)"}

    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]
    service = port_obj.get("service", {}) if port_obj else {}
    tunnel = service.get("tunnel", "")
    protocol = "https" if tunnel else "http"
    verbosity = self.options.get("realtime", False)

    url = f"{protocol}://{host}:{port}/"

    with tempfile.NamedTemporaryFile(delete=False, suffix='.json') as tmp_file:
        output_path = tmp_file.name

    cmd = f"whatweb {url} -p -a=4 -v --log-json={output_path}"
    logging.info(f"[enum_http_whatweb] Executing: {cmd}")

    try:
        # Set a reasonable timeout of 30 seconds for WhatWeb
        timeout = 30
        
        if verbosity:
            from core.logging import run_and_log
            # Add timeout to run_and_log
            run_and_log(cmd, very_verbose=True, timeout=timeout)
        else:
            subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                check=True,
                timeout=timeout
            )
        logging.info(f"[enum_http_whatweb] Done; wrote to {output_path}")
        with open(output_path, "r") as f:
            whatweb_data = json.load(f)
        return {"cmd": cmd, "results": whatweb_data, "report_fields": ["plugins", "error"]}

    except Exception as e:
        logging.error(f"[enum_http_whatweb] Error during WhatWeb scan: {e}")
        return {"cmd": cmd, "error": str(e), "results": {}, "report_fields": ["plugins", "error"]}

enum_http_whatweb.depends_on = ["scan_tcp_scanner","enum_http_curl_confirmation"]