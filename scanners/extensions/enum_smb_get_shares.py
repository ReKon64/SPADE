from core.imports import *
from scanners.scanner import Scanner



@Scanner.extend
def enum_smb_get_shares(self, plugin_results=None):
    """
    List SMB shares using smbclient, then recursively enumerate contents and check read/write/append privileges.
    Returns:
        dict: Results of the smbclient shares command and per-share content/privileges.
    """
    if plugin_results is None:
        plugin_results = {}
    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]
    verbosity = self.options.get("realtime", False)
    results = {}

    try:
        # List shares with proper UNC path format
        cmd = f"smbclient -N -L //{host} -p {port}"
        logging.info(f"Executing: {cmd}")
        if verbosity:
            from core.logging import run_and_log
            shares_output = run_and_log(cmd, very_verbose=True)
        else:
            shares_output = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30
            ).stdout

        results["shares_output"] = shares_output

        # Parse share names from output (look for lines like: "Sharename       Type      Comment")
        shares = []
        in_share_section = False
        for line in shares_output.splitlines():
            if re.match(r"^\s*Sharename\s+Type\s+Comment", line):
                in_share_section = True
                continue
            if in_share_section:
                if line.strip() == "" or line.strip().startswith("---------"):
                    continue
                if re.match(r"^\s*Server\s+Comment", line) or re.match(r"^\s*Workgroup\s+Master", line):
                    break
                parts = line.strip().split()
                if len(parts) >= 2:
                    # Extract only the share name, removing any trailing characters
                    share_name = parts[0].strip()
                    # Skip system shares
                    if share_name not in ["IPC$", "print$"]:
                        shares.append(share_name)
        
        logging.info(f"Detected shares: {shares}")
        results["shares"] = {}

        # For each share, recursively list contents and check privileges
        for share in shares:
            share_info = {"files": [], "dirs": [], "readable": [], "writable": [], "appendable": [], "errors": []}
            # List all files/dirs recursively with proper UNC path format
            list_cmd = f"smbclient -N //{host}/{share} -p {port} -c 'recurse ON; ls'"
            logging.info(f"Listing contents of share {share}: {list_cmd}")
            
            try:
                if verbosity:
                    from core.logging import run_and_log
                    share_list_output = run_and_log(list_cmd, very_verbose=True)
                else:
                    proc = subprocess.run(
                        list_cmd,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=60
                    )
                    share_list_output = proc.stdout + proc.stderr

                # Check for NT_STATUS_BAD_NETWORK_NAME error
                if "NT_STATUS_BAD_NETWORK_NAME" in share_list_output:
                    share_info["errors"].append(f"Failed to connect to share: NT_STATUS_BAD_NETWORK_NAME")
                    results["shares"][share] = share_info
                    continue
                
                share_info["raw_list"] = share_list_output

                # Parse files and directories
                for line in share_list_output.splitlines():
                    # Typical output: "  .                                   D        0  Wed May 14 16:23:44 2025"
                    # The regex accepts both 'D' (directory) and 'N' (normal file) type markers
                    m = re.match(r"^\s*(.+?)\s+(D|N|A)\s+\d+\s+\w+\s+\w+\s+\d+\s+[\d:]+", line)
                    if m:
                        name = m.group(1).strip()
                        typ = m.group(2)
                        if name in [".", ".."]:
                            continue
                        if typ == "D":
                            share_info["dirs"].append(name)
                        else:
                            share_info["files"].append(name)

                # Only proceed if we found files or directories
                if share_info["dirs"] or share_info["files"]:
                    # Check read permissions on each file and directory
                    for path in share_info["dirs"] + share_info["files"]:
                        # Try to read the file/dir
                        read_cmd = f"smbclient -N //{host}/{share} -p {port} -c 'get \"{path}\" /dev/null'"
                        try:
                            read_proc = subprocess.run(
                                read_cmd,
                                shell=True,
                                capture_output=True,
                                text=True,
                                timeout=10
                            )
                            # Check if the command completed successfully
                            if read_proc.returncode == 0 or "NT_STATUS_OK" in read_proc.stdout:
                                share_info["readable"].append(path)
                        except Exception as e:
                            share_info["errors"].append(f"Read error on {path}: {str(e)}")

                        # Try to write a file in the directory (for dirs only)
                        if path in share_info["dirs"]:
                            testfile = "spade_write_test.txt"
                            write_cmd = f"smbclient -N //{host}/{share} -p {port} -c 'cd \"{path}\"; put /etc/hosts {testfile}; del {testfile}'"
                            try:
                                write_proc = subprocess.run(
                                    write_cmd,
                                    shell=True,
                                    capture_output=True,
                                    text=True,
                                    timeout=10
                                )
                                if write_proc.returncode == 0 or "NT_STATUS_OK" in write_proc.stdout:
                                    share_info["writable"].append(path)
                            except Exception as e:
                                share_info["errors"].append(f"Write error on {path}: {str(e)}")

                    # Check append permissions on files
                    # for file in share_info["files"]:
                    #     # Create a temp file with a unique string to append
                    #     with tempfile.NamedTemporaryFile("w+", delete=False) as tmpf:
                    #         tmpf.write("SPADE_APPEND_TEST\n")
                    #         tmpf.flush()
                    #         tmpf_path = tmpf.name
                    #     
                    #     # Use correct UNC path format for append
                    #     append_cmd = (
                    #         f"smbclient -N //{host}/{share} -p {port} "
                    #         f"-c 'prompt OFF; lcd {os.path.dirname(tmpf_path)}; append {os.path.basename(tmpf_path)} \"{file}\"'"
                    #     )
                    #     try:
                    #         append_proc = subprocess.run(
                    #             append_cmd,
                    #             shell=True,
                    #             capture_output=True,
                    #             text=True,
                    #             timeout=10
                    #         )
                    #         if append_proc.returncode == 0 or "NT_STATUS_OK" in append_proc.stdout:
                    #             share_info["appendable"].append(file)
                    #     except Exception as e:
                    #         share_info["errors"].append(f"Append error on {file}: {str(e)}")
                    #     finally:
                    #         try:
                    #             os.unlink(tmpf_path)
                    #         except:
                    #             pass  # Ignore failure to delete temp file

                results["shares"][share] = share_info

            except Exception as e:
                share_info["errors"].append(f"Error accessing share {share}: {str(e)}")
                results["shares"][share] = share_info

    except Exception as e:
        logging.error(f"SMB share enumeration error: {str(e)}")
        results["error"] = str(e)

    # Add report_fields for better display in the report
    return {
        "cmd": cmd, 
        "results": results, 
        "report_fields": ["shares", "error"]
    }

enum_smb_get_shares.depends_on = ["scan_tcp_scanner"]