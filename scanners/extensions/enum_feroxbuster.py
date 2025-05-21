from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def enum_feroxbuster(self):
    """
    Run feroxbuster against the current HTTP(S) port using one or more wordlists.
    Returns:
        dict: { "cmd": [list of commands], "results": { ... } }
    """

    port_obj = self.options["current_port"].get("port_obj", {})
    plugins = port_obj.get("plugins", {})
    curl_result = plugins.get("enum_curl_confirmation", {})
    if not (isinstance(curl_result, dict) and curl_result.get("isreal") is True):
        return {"skipped": "Not a real HTTP(S) service (isreal != True)"}

    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]
    service = port_obj.get("service", {}) if port_obj else {}
    tunnel = service.get("tunnel", "")
    protocol = "https" if tunnel else "http"
    verbosity = self.options.get("realtime", False)

    url = f"{protocol}://{host}:{port}"

    # Support multiple wordlists
    wordlists = self.options.get("ferox_wordlists") or [
        "/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-files.txt"
    ]
    results = {}
    cmds = []

    for wordlist in wordlists:
        with tempfile.NamedTemporaryFile(delete=False, suffix='.ferox') as tmp_file:
            output_path = tmp_file.name

        cmd = (
            f"feroxbuster --url {url} --extract-links -B --auto-tune "
            f"-w {wordlist} --threads 32 --insecure -o {output_path} -C 404 --scan-dir-listings"
        )
        cmds.append(cmd)
        logging.info(f"[*] Executing: {cmd}")

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

            # Parse a summary from the output file
            with open(output_path, "r") as f:
                lines = f.readlines()
            found = [line for line in lines if line.strip() and not line.startswith("#")]
            summary = {
                "found_count": len(found),
                "first_10_results": found[:10]
            }

            results[wordlist] = {
                "output_path": output_path,
                "summary": summary
            }

        except Exception as e:
            logging.error(f"[!] Error during enum_feroxbuster scan against {host} with {wordlist}: {e}")
            results[wordlist] = {"error": str(e)}

    return {"cmd": cmds, "results": results}