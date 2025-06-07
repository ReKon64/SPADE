# Credential List
| Username   | Password     | SSH | FTP | SMB | MySQL        | Privileges        |
|------------|--------------|-----|-----|-----|--------------|-------------------|
| root       | password123  | ✓   | ✗   | ✗   | ✓ (remote)   | System            |
| admin      | admin        | ✓   | ✓   | ✓   | ✓            | Local admin       |
| testuser   | test123      | ✓   | ✓   | ✓   | ✗            | Standard user     |
| guest      | guest        | ✓   | ✓   | ✓   | ✓ (read-only)| Guest access      |
| wpuser     | wppass       | ✗   | ✗   | ✗   | ✓            | WordPress DB      |
| anonymous  | (blank)      | ✗   | ✓   | ✗   | ✗            | FTP only          |
| (empty)    | (blank)      | ✗   | ✗   | ✗   | ✓            | MySQL testdb      |


# Service List
| Service  | Port | Protocol | Default Creds          | Vulnerabilities                                  |
|----------|------|----------|------------------------|--------------------------------------------------|
| SSH      | 2222 | TCP      | root:password123       | Weak passwords, root login, old protocol support |
| FTP      | 2121 | TCP      | anonymous:(blank)      | Anonymous write access, no chroot,               |
| HTTP     | 8080 | TCP      | N/A                    | WordPress, info disclosure, command injection    |
| SMB      | 1445 | TCP      | admin:admin            | Guest shares, weak auth, world-writable          |
| NetBIOS  | 1139 | TCP      | admin:admin            | Null sessions, enumeration                       |
| NFS      | 2049 | TCP      | N/A                    | no_root_squash, world exports                    |
| RPC      | 1111 | TCP      | N/A                    | Service enumeration                              |
| SNMP     | 161  | UDP      | public/private         | Broken                                           |
| SMTP     | 1025 | TCP      | N/A                    | Open relay potential                             |
| MySQL    | 3306 | TCP      | root:(blank)           | Remote root, weak passwords                      |


SSH - works
FTP - maybe fixed, forced to passive
SMB - Seems fine. Listing, login, file get, admin works too
NFS - No RPC = limited functionality, maybe fixed
HTTP - Wordpress is not configured
SNMP - broken 


# Building & Running
docker build -t vulnscanner-linux-target .

## Port mapping / running
sudo docker run -d \
  --name vulnlab-linux \
  --hostname vulnlab-target \
  -p 2222:22 \
  -p 2121:21 \
  -p 8080:80 \
  -p 1139:139 \
  -p 1445:445 \
  -p 1111:111 \
  -p 12049:2049 \
  -p 1161:161/udp \
  -p 1025:25 \
  -p 13306:3306 \
  -p 30000-30009:30000-30009 \
  vulnscanner-linux-target

# Cycle
sudo docker stop vulnlab-linux && \
sudo docker rm vulnlab-linux && \
sudo docker rmi vulnscanner-linux-target && \
sudo docker build -t vulnscanner-linux-target .