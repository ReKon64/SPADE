# SPADE Plugin Development / Style Guide

This guide explains how to write robust, dependency-aware plugins for SPADE, using the `enum_http_whatweb` plugin as a template. 

It covers plugin structure, best practices, and the rationale behind key design decisions; especially the use of `plugin_results` vs `port_obj["plugins"]`.

---

## 1. Naming Convention

**All plugin functions must follow a strict naming convention:**
- Start with a prefix indicating the target protocol/service (e.g., `enum_http_`, `enum_ftp_`, `brute_ssh_`).
- Use lowercase letters and underscores.
- Make the function name descriptive of the action or tool.

**Example:**
```python
@Scanner.extend
def enum_http_whatweb(self, plugin_results=None):
    ...
```

**Why?**
- SPADE uses reflection to auto-discover plugins by prefix for each service.
- Prefixes are mapped to service types in the scanner logic, ensuring only relevant plugins run for each detected service.
- The `enum_generic_` prefix is a catch-all for plugins that should run against all services.

---

## 2. Plugin Structure

A SPADE plugin is a Python function registered with `@Scanner.extend`. It should:

- Import dependencies at the top of the file.
- Accept `self` and `plugin_results=None` as arguments.
- Use `plugin_results` to access results from dependencies.
- Return a dictionary with at least `"cmd"` and `"results"` keys.
- Declare dependencies via a `depends_on` attribute after the function.
- Use helper functions with a `_func` suffix if needed.

**Example:**
```python
from core.imports import *
from scanners.scanner import Scanner

@Scanner.extend
def enum_http_whatweb(self, plugin_results=None):
    # Plugin logic here
    return {"cmd": cmd, "results": whatweb_data}

enum_http_whatweb.depends_on = ["enum_http_curl_confirmation"]
```

---

## 3. Arguments

- **self**: The plugin is a method bound to a Scanner instance, giving access to scan options and the current port context via `self.options`.
- **plugin_results**: A dictionary containing the results of all plugins that have already run for this port in the current scan execution.

**Why use `plugin_results`?**
- Avoids race conditions: `plugin_results` is always up-to-date during plugin execution, unlike `port_obj["plugins"]` which may not be updated until all plugins finish.
- Ensures dependency safety: You can safely access dependency results from `plugin_results`.

---

## 4. Accessing Port and Service Data

Use `self.options["current_port"]` and its `port_obj` key to access static port/service information.

**Example:**
```python
port_obj = self.options["current_port"].get("port_obj", {})
host = self.options["current_port"]["host"]
port = self.options["current_port"]["port_id"]
service = port_obj.get("service", {}) if port_obj else {}
```

---

## 5. Accessing Dependency Results

Use `plugin_results.get("dependency_plugin_name", {})` to access the results of a dependency.

**Example:**
```python
curl_result = plugin_results.get("enum_http_curl_confirmation", {})
isreal = False
if isinstance(curl_result, dict):
    if isinstance(curl_result.get("results"), dict):
        isreal = curl_result["results"].get("isreal") is True
```

---

## 6. Returning Results

Always return a dictionary with:
- `"cmd"`: The command(s) or action(s) performed.
- `"results"`: The parsed or raw results, or a structured error/skipped message.

**Example:**
```python
cmd = f"whatweb {url} -p -a 4 -v --log-json={output_path}"
return {"cmd": cmd, "results": whatweb_data}
```

If your plugin is skipped due to a dependency:
```python
return {"skipped": "Reason for skipping"}
```

---

## 7. Declaring Dependencies

If your plugin requires another plugin to run first, declare this with a `depends_on` attribute after the function.

**Example:**
```python
enum_http_whatweb.depends_on = ["enum_http_curl_confirmation"]
```

- This ensures the scheduler runs dependencies first and passes their results in `plugin_results`.
- You can depend on multiple plugins by listing them all.

---

## 8. Best Practices

- Use `plugin_results` for dependency data.
- Never write to `plugin_results` directly; just return your result.
- Return structured results with `"cmd"` and `"results"` keys.
- Declare dependencies with `depends_on` after the function.
- Log important actions and errors for debugging, but keep logs clear and concise.

---

## 9. Skipping Plugins: The Standard

If your plugin cannot or should not run (e.g., a dependency result means it's not applicable), **always return a dictionary with a `"skipped"` key**:

```python
return {"skipped": "Reason for skipping"}
```

- This allows the scheduler to recognize that the plugin was intentionally skipped and to propagate this status to dependent plugins.
- Do **not** just return an empty dict or a non-standard structure.

**Example:**
```python
if not isreal:
    return {"skipped": "Not a real HTTP(S) service (isreal != True)"}
```

---

## 10. FAQ

**Q: Why not just use `port_obj["plugins"]` for dependencies?**  
A: Because it may not be updated until all plugins for the port finish, leading to race conditions and missing data during parallel execution. `plugin_results` is always up-to-date for the current execution context.

**Q: Why not just use `plugin_results` for everything?**  
A: `plugin_results` is granular and ephemeral, for inter-plugin communication within a single scan context. `port_obj` is broad and persistent, holding static scan context. Keeping them separate avoids race conditions and keeps scan context clear.

**Q: Can I depend on multiple plugins?**  
A: Yes, set `depends_on` to a list of plugin names.

**Q: What if my plugin doesn't access data returned by other plugins?**  
A: The scheduler still requires all plugins to accept `plugin_results`, even if you don't use it.

---