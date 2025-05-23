# SPADE Plugin Development Guide

This guide explains how to write robust, dependency-aware plugins for SPADE, using the `enum_http_whatweb` plugin as a template. 

It covers plugin structure, best practices, and the rationale behind key design decisions; especially the use of `plugin_results` vs `port_obj["plugins"]`.

---

## 1. Plugin Structure

A SPADE plugin is a Python function registered with the `@Scanner.extend` decorator. It should:

- Accept `self` and `plugin_results=None` as arguments.
- Use `plugin_results` to access results from other plugins (dependencies).
- Return a dictionary with at least `"cmd"` and `"results"` keys.
- Optionally declare dependencies via a `depends_on` attribute.

**Example:**
```python
@Scanner.extend
def enum_http_whatweb(self, plugin_results=None):
    # ...plugin logic...
    return {"cmd": cmd, "results": whatweb_data}

enum_http_whatweb.depends_on = ["enum_http_curl_confirmation"]
```

## 2. Arguments
### self
The plugin is a method bound to a Scanner instance, giving access to scan options and the current port context via self.options.

### plugin_results
A dictionary containing the results of all plugins that have already run for this port in the current scan execution.

**Why use plugin_results?**

Race condition avoidance:
During parallel execution, results in the main port object `port_obj["plugins"]` may not be updated until all plugins finish.
`plugin_results` is an in-memory, per-thread, per-port dictionary that is always up-to-date during plugin execution.

Dependency safety:
When your plugin depends on another (e.g., `enum_http_whatweb` depends on `enum_http_curl_confirmation`), you can safely access its result from plugin_results and be sure it is available.
## 3. Accessing Port and Service Data
Use `self.options["current_port"]` and its `port_obj` key to access static port/service information:
```python
port_obj = self.options["current_port"].get("port_obj", {})
host = self.options["current_port"]["host"]
port = self.options["current_port"]["port_id"]
service = port_obj.get("service", {}) if port_obj else {}
```

## 4. Accessing Dependency Results
Use `plugin_results.get("dependency_plugin_name", {})` to access the results of a dependency:
```python
curl_result = plugin_results.get("enum_http_curl_confirmation", {})
isreal = False
if isinstance(curl_result, dict):
    if isinstance(curl_result.get("results"), dict):
        isreal = curl_result["results"].get("isreal") is True
```
## 5. Returning Results
Always return a dictionary with:

"cmd": The command(s) or action(s) performed (for traceability).

"results": The parsed or raw results, or a structured error/skipped message.

**Example:**
```python
cmd = f"whatweb {url} -p -a 4 -v --log-json={output_path}"
return {"cmd": cmd, "results": whatweb_data}
```
If your plugin is skipped due to a dependency:
```python
return {"cmd": [], "results": {"skipped": "Reason for skipping"}}
```

## 6. Declaring Dependencies
If your plugin requires another plugin to run first, declare this with a depends_on attribute after the function body:
```python
enum_http_whatweb.depends_on = ["enum_http_curl_confirmation"]
```
This ensures the scheduler runs dependencies first and passes their results in plugin_results.
To see an example see; `enum_http_whatweb.py` plugin

## 8. Best Practices
- Always use `plugin_results` for dependency data.
- Never write to `plugin_results` directly; just return your result, the scheduler will handle it.
- Return structured results with "cmd" and "results" keys.
- Declare dependencies with depends_on after the function.
- Log important actions and errors for debugging. Do not over clutter it though. Clarity is verbosity.
## 9. FAQ
### *Q: Why not just use `port_obj["plugins"]` for dependencies?*
A: Because it may not be updated until all plugins for the port finish, leading to race conditions and missing data during parallel execution of multiple plugins against the same port. `plugin_results` is always up-to-date for the current execution context.

### *Q: Why not just use plugin_results for everything, instead of having both plugin_results and port_obj?*

A: The design intentionally separates concerns for clarity, safety, and flexibility:

- `plugin_results` is **granular and ephemeral**: it only contains the results of plugins that have already run during the current scan execution for a specific port. It is meant for inter-plugin communication and dependency resolution within a single scan context. This ensures that plugins always see up-to-date results from their dependencies, avoiding race conditions and stale data.

- `port_obj` is **broad and persistent**: it holds static and persistent information about the port/service (such as host, port number, service name, product, version, etc.) that is required for plugin logic but is not produced by any plugin. This data is available before any plugins run and is not affected by the execution order or timing of plugins.

**Why not merge them?**  
If you used only `plugin_results`, you would lose access to static scan data before any plugin runs, and you would risk mixing persistent scan context with ephemeral plugin output. If you used only `port_obj`, you would risk race conditions and stale data when plugins run in parallel, since plugin results may not be available or up-to-date during execution.

**Summary:**  
- Use `port_obj` for broad, static scan context.
- Use `plugin_results` for granular, up-to-date plugin output and dependencies.
- This separation ensures both safety (no race conditions) and clarity (clear distinction between scan context and plugin results).

*Q: Can I depend on multiple plugins?*
A: Yes, set `depends_on` to a list of plugin names.

*Q: What if my plugin doesn't access data returned by other plugins?*
A: The task scheduler requires all plugins to accept `plugin_results` even if you don't use it.

Happy plugin writing!

