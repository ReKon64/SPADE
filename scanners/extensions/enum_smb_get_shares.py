from core.imports import *
from scanners.scanner import Scanner
import re

@Scanner.extend
def enum_smb_get_shares(self):
    """
    List SMB shares using smbclient, then recursively enumerate contents and check read/write privileges.
    Returns:
        dict: Results of the smbclient shares command and per-share content/privileges.
    """
    host = self.options["current_port"]["host"]
    port = self.options["current_port"]["port_id"]
    verbosity = self.options.get("realtime", False)
    results = {}

    try:
        # List shares
        cmd = f"smbclient -N -L \\\\{host} -p {port}"
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
                parts = line.split()
                if len(parts) >= 2:
                    share_name = parts[0]
                    if share_name not in ["IPC$", "print$"]:
                        shares.append(share_name)

        results["shares"] = {}

        # For each share, recursively list contents and check privileges
        for share in shares:
            share_info = {"files": [], "dirs": [], "readable": [], "writable": []}
            # List all files/dirs recursively
            list_cmd = f"smbclient -N \\\\{host}\\{share} -p {port} -c 'recurse ON; ls'"
            logging.info(f"Listing contents of share {share}: {list_cmd}")
            try:
                if verbosity:
                    share_list_output = run_and_log(list_cmd, very_verbose=True)
                else:
                    share_list_output = subprocess.run(
                        list_cmd,
                        shell=True,
                        capture_output=True,
                        text=True,
                        timeout=60
                    ).stdout
                share_info["raw_list"] = share_list_output

                # Parse files and directories
                for line in share_list_output.splitlines():
                    # Typical output: "  .                                   D        0  Wed May 14 16:23:44 2025"
                    m = re.match(r"^\s*(.+?)\s+(D|A)\s+\d+\s+\w+\s+\w+\s+\d+\s+[\d:]+", line)
                    if m:
                        name = m.group(1).strip()
                        typ = m.group(2)
                        if name in [".", ".."]:
                            continue
                        if typ == "D":
                            share_info["dirs"].append(name)
                        else:
                            share_info["files"].append(name)

                # Check read/write on each dir and file
                for path in share_info["dirs"] + share_info["files"]:
                    # Try to read (cat) the file/dir
                    read_cmd = f"smbclient -N \\\\{host}\\{share} -p {port} -c 'get \"{path}\" /dev/null'"
                    try:
                        read_proc = subprocess.run(
                            read_cmd,
                            shell=True,
                            capture_output=True,
                            text=True,
                            timeout=10
                        )
                        if "NT_STATUS_OK" in read_proc.stdout or read_proc.returncode == 0:
                            share_info["readable"].append(path)
                    except Exception:
                        pass

                    # Try to write a file in the dir (for dirs only)
                    if path in share_info["dirs"]:
                        testfile = "spade_write_test.txt"
                        write_cmd = f"smbclient -N \\\\{host}\\{share} -p {port} -c 'cd \"{path}\"; put /etc/hosts {testfile}; del {testfile}'"
                        try:
                            write_proc = subprocess.run(
                                write_cmd,
                                shell=True,
                                capture_output=True,
                                text=True,
                                timeout=10
                            )
                            if "NT_STATUS_OK" in write_proc.stdout or write_proc.returncode == 0:
                                share_info["writable"].append(path)
                        except Exception:
                            pass

                results["shares"][share] = share_info

            except Exception as e:
                share_info["error"] = str(e)
                results["shares"][share] = share_info

    except Exception as e:
        results["error"] = str(e)

    return results