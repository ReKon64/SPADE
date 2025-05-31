## Changelog

### Added
- **enum_ftp_gather plugin**:  
  - Attempts anonymous FTP login.
  - Recursively lists all files and directories on the FTP server.
  - Downloads all files found to the specified output directory (or current working directory if not set).
  - Returns a structured result with commands run, files downloaded, and any errors encountered.

- **enum_generic_product_search plugin**:  
  - Extracts the product name and first major.minor version from each port.
  - Runs a local `searchsploit` command for `<product> <major.minor> exploit` and returns the first 5 results.
  - Scrapes GitHub for repositories matching the query, returning the first 5 URLs and their titles.
  - Scrapes Google for search results matching the query, returning the first 5 URLs and their titles.
  - All search commands/URLs are included in the output for traceability.

### Changed
- **enum_http_curl_confirmation**:  
  - Now always returns a dict with `cmd` and `results` keys for consistency.
  - Improved error handling and output structure.

- **enum_http_feroxbuster**:  
  - Now adds `-x php` for Apache and `-x asp,aspx` for Windows/IIS products automatically.
  - Returns a dict with `cmd` and `results` keys.
  - Skips execution if the HTTP service is not confirmed as real.

- **enum_http_whatweb**:  
  - Now returns a dict with `cmd` and `results` keys.
  - Skips execution if the HTTP service is not confirmed as real.

- **scanner.py**:  
  - Ensured that a generic plugin (e.g., `enum_generic_product_search`) will always be triggered for unmatched services by adding a fallback regex to the service prefix map.

### Fixed
- Ensured all plugins return results in a consistent schema:  
  - Always include `cmd` (commands/URLs run) and `results` (parsed or scraped output).
- Improved robustness of product/version extraction and search logic in product search plugins.
- Improved error reporting for all plugins.

### Notes
- Google and GitHub scraping may be rate-limited or blocked by CAPTCHAs.
- `searchsploit` must be installed and available in the system PATH for local exploit searching.
- All plugins are now more robust to missing or malformed product/version data.