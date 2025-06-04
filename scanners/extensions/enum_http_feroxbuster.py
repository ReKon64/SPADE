from core.imports import *
from scanners.scanner import Scanner
import tempfile

@Scanner.extend
def enum_http_feroxbuster(self, plugin_results=None):
    """
    Run feroxbuster against the current HTTP(S) port using one or more wordlists.
    Adds -x php for Apache, -x asp,x for Windows IIS.
    Returns:
        dict: { "cmd": [list of commands], "results": { ... } }
    """
    if plugin_results is None:
        plugin_results = {}
    timeout = 180

    port_obj = self.options["current_port"].get("port_obj", {})
    curl_result = plugin_results.get("enum_http_curl_confirmation", {})
    isreal = False
    if isinstance(curl_result, dict):
        if isinstance(curl_result.get("results"), dict):
            isreal = curl_result["results"].get("isreal") is True
    if not isreal:
        logging.debug(f"[enum_http_feroxbuster] Checked enum_http_curl_confirmation {curl_result} for isreal")
        return {"skipped": "Not a real HTTP(S) service (isreal != True)"}

    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]
    service = port_obj.get("service", {}) if port_obj else {}
    tunnel = service.get("tunnel", "")
    protocol = "https" if tunnel else "http"
    verbosity = self.options.get("realtime", False)

    url = f"{protocol}://{host}:{port}"

    # Detect product for extension guessing
    product = port_obj.get("product", "").lower()
    ferox_ext = ""
    if "apache" in product:
        ferox_ext = "-x php"
    elif "iis" in product or "windows" in product:
        ferox_ext = "-x asp,aspx"

    # Support multiple wordlists
    wordlists = self.options.get("ferox_wordlists") or [
        "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt"
    ]
    results = {}
    cmds = []
    logging.info(f"[enum_http_feroxbuster] Using wordlists: {wordlists}")
    for wordlist in wordlists:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.ferox') as tmp_file:
            output_path = tmp_file.name

        cmd = (
            f"feroxbuster --url {url} --extract-links -B --auto-tune "
            f"-w {wordlist} --threads 64 --insecure -o {output_path} -C 404 --scan-dir-listings {ferox_ext} --silent"
        ).strip()
        cmds.append(cmd)
        logging.info(f"[enum_http_feroxbuster] Executing: {cmd}")

        try:
            if verbosity:
                from core.logging import run_and_log
                run_and_log(cmd, very_verbose=True, timeout=timeout)
            else:
                subprocess.run(
                    cmd,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout  # Add timeout parameter
                )
            logging.info(f"[enum_http_feroxbuster] Done; wrote to {output_path}")
            # Parse a summary from the output file
            with open(output_path, "r") as f:
                lines = f.readlines()
            found = [line for line in lines if line.strip() and not line.startswith("#")]

            results[wordlist] = {
                "output_path": output_path,
                "found": found,
                "error": None
            }

        except Exception as e:
            logging.error(f"[!] Error during enum_feroxbuster scan against {host} with {wordlist}: {e}")
            results[wordlist] = {"error": str(e)} #"summary": None}

    # Prepare report_fields for each wordlist
    report_fields = ["results", "error"]
    return {"cmd": cmds, "results": results, "report_fields": report_fields}

enum_http_feroxbuster.depends_on = ["scan_tcp_scanner","enum_http_curl_confirmation"]
