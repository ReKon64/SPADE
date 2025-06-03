#!/bin/bash

echo "Starting Vulnerable Linux Target Setup..."

# Start MySQL to finish configuration
service mysql start
sleep 3

# Initialize WordPress database if needed
mysql -e "USE wordpress; SHOW TABLES;" 2>/dev/null || {
    echo "Initializing WordPress database..."
    mysql wordpress < /var/www/html/wp-admin/install.php 2>/dev/null || true
}

# Export NFS shares
echo "Configuring NFS exports..."
exportfs -a
exportfs -v

# Start supervisor to manage all services
echo "Starting all services via supervisor..."
exec /usr/bin/supervisord -c /etc/supervisor/conf.d/supervisord.conf