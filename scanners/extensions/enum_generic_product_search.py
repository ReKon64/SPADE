from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def enum_generic_product_search(self):
    """
    For each port, grab the product name and run searchsploit, GitHub, and Google searches.
    Uses only the product name and the first major.minor version (e.g., Apache 2.14 from Apache 2.14.2.2).
    Returns:
        dict: { "cmd": [], "results": {product, version, search_version, searchsploit, github, google} }
    """
    port_obj = self.options["current_port"].get("port_obj", {})
    product = port_obj.get("product")
    version = port_obj.get("version", "")
    results = {}
    cmds = []

    if not product:
        return {"cmd": [], "results": {"error": "No product info found for this port."}}

    # Extract the first digit-dot-digit sequence for version (e.g., 2.14 from 2.14.2.2)
    search_version = ""
    m = re.search(r"(\d+\.\d+)", version)
    if m:
        search_version = m.group(1)
        search_query = f"{product} {search_version} exploit"
    else:
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
        logging.debug(f"[GENERIC_SEARCH] Searchsploit query: {search_query} | Error: {e}")
        results["searchsploit_debug"] = {"query": search_query, "results": [f"Error running searchsploit: {e}"]}

    # --- GitHub ---
    github_url = f"https://github.com/search?q={encoded_query}"
    cmds.append(github_url)
    github_links = []
    github_titles = []
    try:
        resp = requests.get(github_url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
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
        logging.debug(f"[GENERIC_SEARCH] GitHub query: {search_query} | Results: {github_links}")
        results["github_debug"] = {"query": search_query, "results": github_links}
    except Exception as e:
        results["github"] = [[f"Error searching GitHub: {e}"], []]
        logging.debug(f"[GENERIC_SEARCH] GitHub query: {search_query} | Error: {e}")
        results["github_debug"] = {"query": search_query, "results": [f"Error searching GitHub: {e}"]}

    # --- Google ---
    google_url = f"https://www.google.com/search?q={encoded_query}"
    cmds.append(google_url)
    google_links = []
    google_titles = []
    try:
        resp = requests.get(google_url, timeout=15, headers={"User-Agent": "Mozilla/5.0"})
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
        logging.debug(f"[GENERIC_SEARCH] Google query: {search_query} | Results: {google_links}")
        results["google_debug"] = {"query": search_query, "results": google_links}
    except Exception as e:
        results["google"] = [[f"Error searching Google: {e}"], []]
        logging.debug(f"[GENERIC_SEARCH] Google query: {search_query} | Error: {e}")
        results["google_debug"] = {"query": search_query, "results": [f"Error searching Google: {e}"]}

    results.update({
        "product": product,
        "version": version,
        "search_version": search_version,
        "search_query": search_query
    })

    return {"cmd": cmds, "results": results}