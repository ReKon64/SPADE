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
    port_obj = self.options["current_port"].get("port_obj", {})
    service = port_obj.get("service", {})
    product = service.get("product")
    version = service.get("version", "")
    search_version = ""

    if plugin_results is None:
        plugin_results = {}
    cmds = []
    results = {}
    port_id = self.options['current_port'].get('port_id')
    host = self.options['current_port'].get('host')
    logging.debug(f"[GENERIC_SEARCH] Running generic product search for {host}:{port_id} | {product}:{version}")
    if not product:
        logging.warning(f"[GENERIC_SEARCH] No product info found for {host}:{port_id}:{product}.")
        return {
            "cmd": cmds,
            "results": {"error": "No product info found for this port."}
        }

    # Extract the first digit-dot-digit sequence for version (e.g., 2.14 from 2.14.2.2)
    m = re.search(r"(\d+\.\d+)", version)
    if m:
        search_version = m.group(1)
        search_query = f"{product} {search_version} exploit"
        logging.debug(f"[GENERIC_SEARCH] Using search_version '{search_version}' for product '{product}' on {host}:{port_id}")
    else:
        if version:
            logging.debug(f"[GENERIC_SEARCH] Unexpected version format: '{version}' for product '{product}'. Falling back to product + version.")
            search_query = f"{product} {version} exploit"
        else:
            logging.debug(f"[GENERIC_SEARCH] No version info for product '{product}' on {host}:{port_id}. Using product only.")
            search_query = f"{product} exploit"

    encoded_query = urllib.parse.quote_plus(search_query)
    logging.info(f"[GENERIC_SEARCH] Search query for {host}:{port_id}: {search_query}")

    # --- Searchsploit ---
    searchsploit_cmd = f"searchsploit {product} {search_version}"
    cmds.append(searchsploit_cmd)
    logging.debug(f"[GENERIC_SEARCH] Built Searchsploit command: {searchsploit_cmd}")
    try:
        logging.debug(f"[GENERIC_SEARCH] Running Searchsploit command: {searchsploit_cmd}")
        proc = subprocess.run(
            searchsploit_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=15
        )
        logging.debug(f"[GENERIC_SEARCH] Searchsploit stdout: {proc.stdout}")
        logging.debug(f"[GENERIC_SEARCH] Searchsploit stderr: {proc.stderr}")
        lines = [line for line in proc.stdout.splitlines() if line.strip() and not line.startswith(("-", "=", "Exploit Title"))]
        results["searchsploit"] = lines[:5]
        logging.info(f"[GENERIC_SEARCH] Searchsploit results for {host}:{port_id}: {lines[:5]}")
        results["searchsploit_debug"] = {"query": search_query, "results": lines[:5]}
    except Exception as e:
        results["searchsploit"] = [f"Error running searchsploit: {e}"]
        logging.warning(f"[GENERIC_SEARCH] Searchsploit query: {search_query} | Error: {e}")
        results["searchsploit_debug"] = {"query": search_query, "results": [f"Error running searchsploit: {e}"]}

    # --- GitHub (API only, skip if no API key) ---
    github_links = []
    github_titles = []
    github_status = None
    github_api_key = self.options.get("github_api_key")
    github_url = f"https://github.com/search?q={encoded_query}"
    cmds.append(github_url)
    logging.debug(f"[GENERIC_SEARCH] Built GitHub URL: {github_url}")
    logging.debug(f"[GENERIC_SEARCH] Using GitHub API key: {github_api_key}")

    if github_api_key:
        try:
            headers = {
                "Authorization": f"token {github_api_key}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "Mozilla/5.0"
            }
            api_url = f"https://api.github.com/search/repositories?q={encoded_query}"
            logging.debug(f"[GENERIC_SEARCH] Sending GitHub API request: {api_url}")
            resp = requests.get(api_url, headers=headers, timeout=15)
            github_status = resp.status_code
            resp.raise_for_status()
            items = resp.json().get("items", [])
            for item in items[:5]:
                github_links.append(item.get("html_url"))
                github_titles.append(item.get("full_name"))
            results["github"] = [github_links, github_titles]
            results["github_status"] = github_status
            logging.debug(f"[GENERIC_SEARCH] GitHub API query: {search_query} | Results: {github_links} | Status: {github_status}")
            results["github_debug"] = {"query": search_query, "results": github_links}
        except Exception as e:
            logging.warning(f"[GENERIC_SEARCH] GitHub API failed: {e}")
            results["github"] = [[f"Error searching GitHub API: {e}"], []]
            results["github_status"] = github_status
            results["github_debug"] = {"query": search_query, "results": [f"Error searching GitHub API: {e}"]}
    else:
        logging.warning("[GENERIC_SEARCH] No GitHub API key found, skipping GitHub search.")
        results["github"] = {"skipped": "No GitHub API key provided, skipping GitHub search."}
        results["github_status"] = None
        results["github_debug"] = {"query": search_query, "results": ["No GitHub API key provided, skipping GitHub search."]}

    # --- Google Custom Search JSON API with DuckDuckGo fallback ---
    google_links = []
    google_titles = []
    google_status = None
    google_api_key = self.options.get("google_api_key")
    google_cse_id = self.options.get("google_cse_id")
    google_url = f"https://www.googleapis.com/customsearch/v1"
    cmds.append(f"Google Custom Search API: {search_query}")
    logging.debug(f"[GENERIC_SEARCH] Using Google API key: {google_api_key} | CSE ID: {google_cse_id}")

    if google_api_key and google_cse_id:
        try:
            params = {
                "q": search_query,
                "key": google_api_key,
                "cx": google_cse_id,
                "num": 5
            }
            logging.debug(f"[GENERIC_SEARCH] Sending Google Custom Search API request: {params}")
            resp = requests.get(google_url, params=params, timeout=15)
            google_status = resp.status_code
            resp.raise_for_status()
            items = resp.json().get("items", [])
            for item in items:
                google_links.append(item.get("link"))
                google_titles.append(item.get("title"))
            results["google"] = [google_links, google_titles]
            results["google_status"] = google_status
            logging.debug(f"[GENERIC_SEARCH] Google Custom Search API query: {search_query} | Results: {google_links} | Status: {google_status}")
            results["google_debug"] = {"query": search_query, "results": google_links}
        except Exception as e:
            logging.warning(f"[GENERIC_SEARCH] Google Custom Search API failed: {e} | Falling back to DuckDuckGo.")
            results["google"] = [[f"Error searching Google API: {e}"], []]
            results["google_status"] = google_status
            results["google_debug"] = {"query": search_query, "results": [f"Error searching Google API: {e}"]}
    else:
        logging.warning("[GENERIC_SEARCH] Google API key or CSE ID not set, using DuckDuckGo fallback.")
        results["google"] = [["Google API key or CSE ID not set, using DuckDuckGo fallback."], []]
        results["google_status"] = None
        results["google_debug"] = {"query": search_query, "results": ["Google API key or CSE ID not set, using DuckDuckGo fallback."]}

    # DuckDuckGo fallback if Google failed or returned no results
    if not google_links:
        duckduckgo_url = f"https://html.duckduckgo.com/html/?q={encoded_query}"
        cmds.append(duckduckgo_url)
        ddg_links = []
        ddg_titles = []
        try:
            logging.debug(f"[GENERIC_SEARCH] Sending DuckDuckGo request: {duckduckgo_url}")
            resp = requests.get(duckduckgo_url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
            soup = BeautifulSoup(resp.text, "html.parser")
            for result in soup.select('a.result__a'):
                href = result.get("href")
                title = result.get_text(strip=True)
                if href and title:
                    ddg_links.append(href)
                    ddg_titles.append(title)
                if len(ddg_links) >= 5:
                    break
            # Overwrite google results with DuckDuckGo fallback
            results["google"] = [ddg_links, ddg_titles]
            results["google_status"] = resp.status_code
            results["google_debug"] = {"query": search_query, "results": ddg_links}
            logging.debug(f"[GENERIC_SEARCH] DuckDuckGo fallback query: {search_query} | Results: {ddg_links} | Status: {resp.status_code}")
        except Exception as e:
            results["google"] = [[f"Error searching DuckDuckGo: {e}"], []]
            results["google_status"] = None
            results["google_debug"] = {"query": search_query, "results": [f"Error searching DuckDuckGo: {e}"]}
            logging.warning(f"[GENERIC_SEARCH] DuckDuckGo fallback query: {search_query} | Error: {e}")

    results.update({
        "product": product,
        "version": version,
        "search_version": search_version,
        "search_query": search_query
    })

    logging.info(f"[GENERIC_SEARCH] Final results for {host}:{port_id}: {results}")

    return {"cmd": cmds, "results": results}

# Add UDP Scanner once ready
enum_generic_product_search.depends_on = ["scan_tcp_scanner"]
