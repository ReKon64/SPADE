from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def enum_generic_product_search(self, plugin_results=None):
    """
    For each port, grab the product name and run searchsploit, GitHub, and Google searches.
    Uses only the product name and the first major.minor version (e.g., Apache 2.14 from Apache 2.14.2.2).
    Returns:
        dict: { "cmd": [], "results": {product, version, search_version, searchsploit, github, google} }
    """
    if plugin_results is None:
        plugin_results = {}
    port_obj = self.options["current_port"].get("port_obj", {})
    product = port_obj.get("product")
    cmds = []
    results = {}

    if not product:
        logging.warning("[GENERIC_SEARCH] No product info found for this port.")
        return {
            "cmd": cmds,
            "results": {"error": "No product info found for this port."}
        }

    version = port_obj.get("version", "")
    # Extract the first digit-dot-digit sequence for version (e.g., 2.14 from 2.14.2.2)
    search_version = ""
    m = re.search(r"(\d+\.\d+)", version)
    if m:
        search_version = m.group(1)
        search_query = f"{product} {search_version} exploit"
    else:
        if version:
            logging.debug(f"[GENERIC_SEARCH] Unexpected version format: '{version}' for product '{product}'. Falling back to product + version.")
            search_query = f"{product} {version} exploit"
        else:
            logging.debug(f"[GENERIC_SEARCH] No version info for product '{product}'. Using product only.")
            search_query = f"{product} exploit"

    encoded_query = urllib.parse.quote_plus(search_query)

    # --- Searchsploit ---
    searchsploit_cmd = f"searchsploit \"{search_query}\""
    cmds.append(searchsploit_cmd)
    try:
        proc = subprocess.run(
            searchsploit_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=15
        )
        lines = [line for line in proc.stdout.splitlines() if line.strip() and not line.startswith(("-", "=", "Exploit Title"))]
        results["searchsploit"] = lines[:5]
        logging.debug(f"[GENERIC_SEARCH] Searchsploit query: {search_query} | Results: {lines[:5]}")
        results["searchsploit_debug"] = {"query": search_query, "results": lines[:5]}
    except Exception as e:
        results["searchsploit"] = [f"Error running searchsploit: {e}"]
        logging.warning(f"[GENERIC_SEARCH] Searchsploit query: {search_query} | Error: {e}")
        results["searchsploit_debug"] = {"query": search_query, "results": [f"Error running searchsploit: {e}"]}

    # --- GitHub ---
    github_url = f"https://github.com/search?q={encoded_query}"
    cmds.append(github_url)
    github_links = []
    github_titles = []
    github_status = None
    try:
        resp = requests.get(github_url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        github_status = resp.status_code
        if resp.status_code != 200:
            logging.debug(f"[GENERIC_SEARCH] GitHub query: {search_query} | HTTP status: {resp.status_code}")
        soup = BeautifulSoup(resp.text, "html.parser")
        for a in soup.select('a.v-align-middle'):
            href = a.get("href")
            title = a.get_text(strip=True)
            if href and href.startswith("/"):
                github_links.append("https://github.com" + href)
                github_titles.append(title)
            if len(github_links) >= 5:
                break
        results["github"] = [github_links, github_titles]
        results["github_status"] = github_status
        logging.debug(f"[GENERIC_SEARCH] GitHub query: {search_query} | Results: {github_links} | Status: {github_status}")
        results["github_debug"] = {"query": search_query, "results": github_links}
    except Exception as e:
        results["github"] = [[f"Error searching GitHub: {e}"], []]
        results["github_status"] = github_status
        logging.warning(f"[GENERIC_SEARCH] GitHub query: {search_query} | Error: {e} | Status: {github_status}")
        results["github_debug"] = {"query": search_query, "results": [f"Error searching GitHub: {e}"]}

    # --- Google ---
    google_url = f"https://www.google.com/search?q={encoded_query}"
    cmds.append(google_url)
    google_links = []
    google_titles = []
    google_status = None
    try:
        resp = requests.get(google_url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
        google_status = resp.status_code
        if resp.status_code != 200:
            logging.warning(f"[GENERIC_SEARCH] Google query: {search_query} | HTTP status: {resp.status_code}")
        soup = BeautifulSoup(resp.text, "html.parser")
        for g in soup.select('a'):
            href = g.get("href")
            if href and href.startswith("/url?q="):
                url = href.split("/url?q=")[1].split("&")[0]
                if not url.startswith("https://webcache.googleusercontent.com"):
                    title = g.get_text(strip=True)
                    google_links.append(url)
                    google_titles.append(title)
            if len(google_links) >= 5:
                break
        results["google"] = [google_links, google_titles]
        results["google_status"] = google_status
        logging.debug(f"[GENERIC_SEARCH] Google query: {search_query} | Results: {google_links} | Status: {google_status}")
        results["google_debug"] = {"query": search_query, "results": google_links}
    except Exception as e:
        results["google"] = [[f"Error searching Google: {e}"], []]
        results["google_status"] = google_status
        logging.warning(f"[GENERIC_SEARCH] Google query: {search_query} | Error: {e} | Status: {google_status}")
        results["google_debug"] = {"query": search_query, "results": [f"Error searching Google: {e}"]}

    results.update({
        "product": product,
        "version": version,
        "search_version": search_version,
        "search_query": search_query
    })

    return {"cmd": cmds, "results": results}

# Add UDP Scanner once ready
enum_generic_product_search.depends_on = ["scan_tcp_scanner"]
