from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def enum_http_wpscan(self, plugin_results=None):
    """
    Run wpscan against the current host/port and return parsed results.
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
        logging.debug(f"[enum_http_wpscan] Checked {curl_result} for isreal")
        return {"skipped": "Not a real HTTP(S) service (isreal != True)"}

    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]
    service = port_obj.get("service", {}) if port_obj else {}
    tunnel = service.get("tunnel", "")
    protocol = "https" if tunnel else "http"
    verbosity = self.options.get("realtime", False)

    url = f"{protocol}://{host}:{port}/"

    with tempfile.NamedTemporaryFile(delete=False, suffix='.wpscan.json') as tmp_file:
        output_path = tmp_file.name

    # Add API token if present
    api_token = self.options.get("wpscan_api_token")
    api_token_arg = f"--api-token {api_token}" if api_token else ""

    cmd = (
        f"wpscan --url {url} --plugins-detection aggressive --enumerate ap,at,tt,cb,dbe,u,m "
        f"--no-update --output {output_path} --format json {api_token_arg}".strip()
    )
    logging.info(f"[enum_http_wpscan] Executing: {cmd}")

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

        wpscan_data = {}
        xmlrpc_enabled = False
        if os.path.exists(output_path):
            with open(output_path, "r") as f:
                try:
                    wpscan_data = json.load(f)
                    # Detect if XML-RPC is enabled
                    xmlrpc_info = wpscan_data.get("xml_rpc", {})
                    if isinstance(xmlrpc_info, dict):
                        xmlrpc_enabled = xmlrpc_info.get("enabled", False)
                except Exception as e:
                    logging.warning(f"[enum_http_wpscan] Failed to parse JSON: {e}")

        wpscan_data["xmlrpc_enabled"] = xmlrpc_enabled
        return {"cmd": cmd, "results": wpscan_data, "report_fields": ["xmlrpc_enabled", "error"]}

    except Exception as e:
        logging.error(f"[enum_http_wpscan] Error during wpscan: {e}")
        return {"cmd": cmd, "error": str(e), "results": {}, "report_fields": ["xmlrpc_enabled", "error"]}

enum_http_wpscan.depends_on = ["scan_tcp_scanner", "enum_http_curl_confirmation"]
