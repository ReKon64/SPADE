| Service  | Port | Protocol | Default Creds          | Vulnerabilities                                  |
|----------|------|----------|------------------------|--------------------------------------------------|
| SSH      | 2222 | TCP      | root:password123       | Weak passwords, root login, old protocol support |
| FTP      | 2121 | TCP      | anonymous:(blank)      | Anonymous write access, no chroot                |
| HTTP     | 8080 | TCP      | N/A                    | WordPress, info disclosure, command injection    |
| SMB      | 1445 | TCP      | admin:admin            | Guest shares, weak auth, world-writable          |
| NetBIOS  | 1139 | TCP      | admin:admin            | Null sessions, enumeration                       |
| NFS      | 2049 | TCP      | N/A                    | no_root_squash, world exports                    |
| RPC      | 1111 | TCP      | N/A                    | Service enumeration                              |
| SNMP     | 161  | UDP      | public/private         | Default communities, MIB:Extend Readable Creds   |
| SMTP     | 1025 | TCP      | N/A                    | Open relay potential                             |
| MySQL    | 3306 | TCP      | root:(blank)           | Remote root, weak passwords                      |

