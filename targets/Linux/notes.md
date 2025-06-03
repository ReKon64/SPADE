SSH - works
FTP - maybe fixed
SMB - Seems fine. Listing, login, file get, admin works too
NFS - No RPC = limited functionality, maybe fixed
HTTP - Wordpress is not configured
SNMP - broken 

# Build 
docker build -t vulnscanner-linux-target .
# This will take 5-10 minutes depending on your internet connection

# Port mapping / running
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