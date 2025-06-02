from core.imports import *
from scanners.scanner import Scanner
import base64

@Scanner.extend
def enum_http_gowitness(self, plugin_results=None):
    """
    Run gowitness to screenshot the current HTTP(S) service and return b64-encoded images.
    Returns:
        dict: { "cmd": ..., "results": { "screenshots": [ { "filename": ..., "b64": ... } ] } }
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
        logging.debug(f"[enum_http_gowitness] Checked {curl_result} for isreal")
        return {"skipped": "Not a real HTTP(S) service (isreal != True)"}

    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]
    service = port_obj.get("service", {}) if port_obj else {}
    tunnel = service.get("tunnel", "")
    protocol = "https" if tunnel else "http"
    url = f"{protocol}://{host}:{port}/"

    with tempfile.TemporaryDirectory() as tmpdir:
        screenshot_dir = os.path.join(tmpdir, "screens")
        os.makedirs(screenshot_dir, exist_ok=True)
        cmd = f'gowitness single --url "{url}" --disable-db --destination "{screenshot_dir}"'
        logging.info(f"[enum_http_gowitness] Executing: {cmd}")

        try:
            subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
            screenshots = []
            for fname in os.listdir(screenshot_dir):
                if fname.lower().endswith((".png", ".jpg", ".jpeg")):
                    fpath = os.path.join(screenshot_dir, fname)
                    with open(fpath, "rb") as imgf:
                        b64img = base64.b64encode(imgf.read()).decode("utf-8")
                    screenshots.append({"filename": fname, "b64": b64img})
            return {"cmd": cmd, "results": {"screenshots": screenshots}, "report_fields": ["screenshots", "error"]}
        except Exception as e:
            logging.error(f"[enum_http_gowitness] Error during gowitness: {e}")
            return {"cmd": cmd, "error": str(e), "results": {"screenshots": []}, "report_fields": ["screenshots", "error"]}

enum_http_gowitness.depends_on = ["scan_tcp_scanner", "enum_http_curl_confirmation"]