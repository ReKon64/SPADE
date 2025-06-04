FROM ubuntu:20.04

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update system and install base packages
RUN apt-get update && apt-get install -y \
    openssh-server \
    vsftpd \
    samba \
    rpcbind \
    nfs-kernel-server \
    snmpd \
    snmp \
    postfix \
    apache2 \
    mysql-server \
    php \
    php-mysql \
    php-mysqli \
    wget \
    curl \
    net-tools \
    supervisor \
    nano \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /var/run/sshd /var/log/supervisor /run/php

# Configure SSH - Weak configuration for testing
RUN echo 'root:password123' | chpasswd && \
    useradd -m -s /bin/bash admin && \
    echo 'admin:admin' | chpasswd && \
    useradd -m -s /bin/bash testuser && \
    echo 'testuser:test123' | chpasswd && \
    useradd -m -s /bin/bash guest && \
    echo 'guest:guest' | chpasswd

# SSH Configuration - Insecure settings
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
    echo 'PermitEmptyPasswords yes' >> /etc/ssh/sshd_config && \
    echo 'Protocol 2,1' >> /etc/ssh/sshd_config && \
    echo 'X11Forwarding yes' >> /etc/ssh/sshd_config

# Configure FTP - Insecure settings
RUN echo 'anonymous_enable=YES' >> /etc/vsftpd.conf && \
    mkdir -p /var/run/vsftpd/empty && \
    chmod 755 /var/run/vsftpd/empty && \
    echo 'write_enable=YES' >> /etc/vsftpd.conf && \
    echo 'anon_upload_enable=YES' >> /etc/vsftpd.conf && \
    echo 'anon_mkdir_write_enable=YES' >> /etc/vsftpd.conf && \
    echo 'local_enable=YES' >> /etc/vsftpd.conf && \
    echo 'secure_chroot_dir=/var/run/vsftpd/empty' >> /etc/vsftpd.conf && \
    echo 'chroot_local_user=NO' >> /etc/vsftpd.conf && \
    echo 'allow_writeable_chroot=YES' >> /etc/vsftpd.conf && \
    echo 'listen=YES' >> /etc/vsftpd.conf && \
    echo 'listen_ipv6=NO' >> /etc/vsftpd.conf && \
    echo 'pasv_enable=YES' >> /etc/vsftpd.conf && \
    echo 'pasv_min_port=30000' >> /etc/vsftpd.conf && \
    echo 'pasv_max_port=30009' >> /etc/vsftpd.conf && \
    echo 'pasv_address=127.0.0.1' >> /etc/vsftpd.conf && \
    mkdir -p /srv/ftp && \
    chmod 755 /srv/ftp && \
    echo 'anon_root=/srv/ftp' >> /etc/vsftpd.conf && \
    echo 'ftpd_banner=Welcome to the vulnerable FTP server' >> /etc/vsftpd.conf && \
    echo 'test123:test123' > /srv/ftp/password.txt

# Configure Samba - Weak shares and authentication
RUN cp /etc/samba/smb.conf /etc/samba/smb.conf.bak
COPY smb.conf /etc/samba/smb.conf

# Set SMB passwords for users
RUN printf "admin\nadmin\n" | smbpasswd -a admin -s && \
    printf "test123\ntest123\n" | smbpasswd -a testuser -s && \
    printf "guest\nguest\n" | smbpasswd -a guest -s

# Configure NFS - Insecure exports
RUN echo '/tmp *(rw,sync,no_root_squash,no_subtree_check)' > /etc/exports && \
    echo '/home *(rw,sync,no_root_squash,no_subtree_check)' >> /etc/exports && \
    echo '/srv/ftp *(rw,sync,no_root_squash,no_subtree_check)' >> /etc/exports && \
    echo '/var/www/html *(rw,sync,no_root_squash,no_subtree_check)' >> /etc/exports

# Configure SNMP - Default community strings and weak config
RUN mkdir -p /etc/snmp && \
    snmpconf -g basic_setup -c /etc/snmp/snmpd.conf -q && \
    echo 'rocommunity public' >> /etc/snmp/snmpd.conf && \
    echo 'rwcommunity private' >> /etc/snmp/snmpd.conf && \
    echo 'agentAddress udp:161,udp6:[::1]:161' >> /etc/snmp/snmpd.conf && \
    echo 'sysLocation Vulnerable Lab Environment' >> /etc/snmp/snmpd.conf && \
    echo 'sysContact admin@vulnlab.local' >> /etc/snmp/snmpd.conf && \
    echo 'view systemonly included .1.3.6.1.2.1.1' >> /etc/snmp/snmpd.conf && \
    echo 'view systemonly included .1.3.6.1.2.1.25.1' >> /etc/snmp/snmpd.conf && \
    echo -e "admin:admin\nwpuser:wppass\nftpuser:ftp123\nmysql:rootpass" > /etc/snmp/snmp_creds.txt && \
    chmod 644 /etc/snmp/snmp_creds.txt && \
    echo 'extend creds /bin/cat /etc/snmp/snmp_creds.txt' >> /etc/snmp/snmpd.conf

# Configure MySQL - Weak configuration and users
RUN service mysql start && sleep 5 && \
    mysql -e "CREATE DATABASE wordpress DEFAULT CHARACTER SET utf8 COLLATE utf8_unicode_ci;" && \
    mysql -e "CREATE DATABASE testdb;" && \
    mysql -e "CREATE USER 'wpuser'@'%' IDENTIFIED BY 'wppass';" && \
    mysql -e "GRANT ALL PRIVILEGES ON wordpress.* TO 'wpuser'@'%';" && \
    mysql -e "CREATE USER 'admin'@'%' IDENTIFIED BY 'admin';" && \
    mysql -e "GRANT ALL PRIVILEGES ON *.* TO 'admin'@'%';" && \
    mysql -e "CREATE USER 'root'@'%' IDENTIFIED BY '';" && \
    mysql -e "GRANT ALL PRIVILEGES ON *.* TO 'root'@'%';" && \
    mysql -e "CREATE USER ''@'%' IDENTIFIED BY '';" && \
    mysql -e "GRANT ALL PRIVILEGES ON testdb.* TO ''@'%';" && \
    mysql -e "CREATE USER 'guest'@'%' IDENTIFIED BY 'guest';" && \
    mysql -e "GRANT SELECT ON *.* TO 'guest'@'%';" && \
    mysql -e "FLUSH PRIVILEGES;" && \
    service mysql stop

# Configure MySQL to bind to all interfaces
RUN sed -i 's/bind-address.*=.*/bind-address = 0.0.0.0/' /etc/mysql/mysql.conf.d/mysqld.cnf

# Download and install WordPress
RUN cd /var/www/html && \
    rm -f index.html && \
    wget -q https://wordpress.org/latest.tar.gz && \
    tar xzf latest.tar.gz && \
    mv wordpress/* . && \
    rm -rf wordpress latest.tar.gz

# WordPress configuration with vulnerable settings
RUN cd /var/www/html && \
    cp wp-config-sample.php wp-config.php && \
    sed -i "s/database_name_here/wordpress/" wp-config.php && \
    sed -i "s/username_here/wpuser/" wp-config.php && \
    sed -i "s/password_here/wppass/" wp-config.php && \
    sed -i "s/localhost/127.0.0.1/" wp-config.php && \
    echo "define('WP_DEBUG', true);" >> wp-config.php && \
    echo "define('WP_DEBUG_LOG', true);" >> wp-config.php

# Create vulnerable web files
RUN echo '<?php phpinfo(); ?>' > /var/www/html/info.php && \
    echo '<?php echo "Admin Panel"; if(isset($_GET["cmd"])) { system($_GET["cmd"]); } ?>' > /var/www/html/admin.php && \
    mkdir -p /var/www/html/backup && \
    echo 'admin:admin123' > /var/www/html/backup/passwords.txt && \
    echo 'Database backup file' > /var/www/html/backup/db_backup.sql

# Set proper permissions
RUN chown -R www-data:www-data /var/www/html && \
    chmod -R 755 /var/www/html && \
    chmod 644 /var/www/html/backup/passwords.txt

# Configure Apache with vulnerable settings
RUN echo 'ServerName localhost' >> /etc/apache2/apache2.conf && \
    echo 'ServerTokens Full' >> /etc/apache2/apache2.conf && \
    echo 'ServerSignature On' >> /etc/apache2/apache2.conf && \
    a2enmod rewrite && \
    a2enmod info && \
    a2enmod status

# Configure Postfix (basic SMTP)
RUN echo 'postfix postfix/mailname string vulnlab.local' | debconf-set-selections && \
    echo 'postfix postfix/main_mailer_type string "Internet Site"' | debconf-set-selections && \
    postconf -e 'disable_vrfy_command = no'

# Create test files and directories
RUN mkdir -p /tmp/shared && \
    echo 'This is a shared file accessible via NFS' > /tmp/shared/readme.txt && \
    chmod 777 /tmp/shared && \
    echo 'Sensitive information in temp file' > /tmp/secrets.txt

# Copy supervisor configuration
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Copy setup script
COPY setup.sh /setup.sh
RUN chmod +x /setup.sh

# Expose all service ports
EXPOSE 21 22 25 80 111 139 161/udp 445 993 995 2049 3306 30000-30009

# Set entrypoint
CMD ["/setup.sh"]