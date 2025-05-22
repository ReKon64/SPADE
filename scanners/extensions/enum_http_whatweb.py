# File: scanners/enum_http_whatweb.py
from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def enum_http_whatweb(self):
    """
    Run WhatWeb against the current host/port and return parsed results.
    Only runs if the port's plugins['enum_curl_confirmation']['isreal'] is True.
    Returns:
        dict: { "cmd": ..., "results": ... }
    """
    import tempfile
    import json

    port_obj = self.options["current_port"].get("port_obj", {})
    # Check if curl confirmation plugin ran and isreal is True
    plugins = port_obj.get("plugins", {})
    curl_result = plugins.get("enum_curl_confirmation", {})
    if not (isinstance(curl_result, dict) and curl_result.get("isreal") is True):
        logging.debug(f"[enum_http_feroxbuster] Checked {curl_result} for isreal")
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

    cmd = f"whatweb {url} -p -a 4 -v --log-json={output_path}"
    logging.info(f"[enum_http_whatweb] Executing: {cmd}")

    try:
        if verbosity:
            from core.logging import run_and_log
            run_and_log(cmd, very_verbose=True)
        else:
            subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                check=True
            )

        with open(output_path, "r") as f:
            whatweb_data = json.load(f)
        return {"cmd": cmd, "results": whatweb_data}

    except Exception as e:
        logging.error(f"[enum_http_whatweb] Error during WhatWeb scan: {e}")
        return {"cmd": cmd, "error": str(e)}