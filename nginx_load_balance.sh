#!/bin/bash
# Install Elastic data node using Cloudformation template

touch /tmp/deploy.log

echo "Nginx Load Balancing: Starting process." > /tmp/deploy.log
ssh_username="wazuh_elastic"
ssh_password="2021"
eth0_ip=$(hostname -I |  head -1 | cut -d' ' -f1)
node_name=3
echo "Added env vars." >> /tmp/deploy.log
echo "eth0_ip: $eth0_ip" >> /tmp/deploy.log

check_root(){
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo "NOT running as root. Exiting" >> /tmp/deploy.log
        echo "This script must be run as root"
        exit 1
    fi
    echo "Running as root." >> /tmp/deploy.log
}

create_ssh_user(){
    # Creating SSH user
    if ! id -u ${ssh_username} > /dev/null 2>&1; then adduser ${ssh_username}; fi
    echo "${ssh_username} ALL=(ALL)NOPASSWD:ALL" >> /etc/sudoers
    usermod --password $(openssl passwd -1 ${ssh_password}) ${ssh_username}
    echo "Created SSH user." >> /tmp/deploy.log

    sed -i 's|[#]*PasswordAuthentication no|PasswordAuthentication yes|g' /etc/ssh/sshd_config
    systemctl restart sshd
    echo "Started SSH service." >> /tmp/deploy.log
}


install_nginx(){
    
    #Install dependencies
    yum install curl unzip wget libcap -y
    yum install epel-release -y
    echo "Dependencies are installed." >> /tmp/deploy.log

    # Installing NGINX
    yum install nginx -y
    echo "Installed NGINX." >> /tmp/deploy.log
}

configuring_load_balancer(){
    echo "Adding wazuh instances to NGINX." >> /tmp/deploy.log

    cat > /etc/nginx/conf.d/load_balancer.conf << EOF
    stream {
    upstream master {
        server 192.168.1.205:1515;
    }
    upstream workers {
    hash $remote_addr consistent;
        server 192.168.1.205:1514;
        server 192.168.1.206:1514;
    }
    server {
        listen 1515;
        proxy_pass master;
    }
    server {
        listen 1514;
        proxy_pass workers;
    }
}
EOF

echo "Added wazuh instances to NGINX configuration file." >> /tmp/deploy.log

cat > /etc/nginx/nginx.conf << EOF
# For more information on configuration, see:
#   * Official English Documentation: http://nginx.org/en/docs/
#   * Official Russian Documentation: http://nginx.org/ru/docs/

user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

# Load dynamic modules. See /usr/share/doc/nginx/README.dynamic.
include /usr/share/nginx/modules/*.conf;
include /etc/nginx/conf.d/*.conf;

events {
    worker_connections 1024;
}

http {
    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" "$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 2048;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    # Load modular configuration files from the /etc/nginx/conf.d directory.
    # See http://nginx.org/en/docs/ngx_core_module.html#include
    # for more information.
    

    server {
        listen       80 default_server;
        listen       [::]:80 default_server;
        server_name  _;
        root         /usr/share/nginx/html;

        # Load configuration files for the default server block.
        include /etc/nginx/default.d/*.conf;

        location / {
        }

        error_page 404 /404.html;
            location = /40x.html {
        }

        error_page 500 502 503 504 /50x.html;
            location = /50x.html {
        }
    }

# Settings for a TLS enabled server.
#    server {
#        listen       443 ssl http2 default_server;
#        listen       [::]:443 ssl http2 default_server;
#        server_name  _;
#        root         /usr/share/nginx/html;
#
#        ssl_certificate "/etc/pki/nginx/server.crt";
#        ssl_certificate_key "/etc/pki/nginx/private/server.key";
#        ssl_session_cache shared:SSL:1m;
#        ssl_session_timeout  10m;
#        ssl_ciphers PROFILE=SYSTEM;
#        ssl_prefer_server_ciphers on;
#
#        # Load configuration files for the default server block.
#        include /etc/nginx/default.d/*.conf;
#
#        location / {
#        }
#
#        error_page 404 /404.html;
#            location = /40x.html {
#        }
#
#        error_page 500 502 503 504 /50x.html;
#            location = /50x.html {
#        }
#    }

}
EOF

echo "NGINX configuration completed." >> /tmp/deploy.log

systemctl enable nginx
systemctl start nginx
echo "NGINX service started." >> /tmp/deploy.log

sed -i -e "s#SELINUX=enforcing#SELINUX=disabled#" /etc/sysconfig/selinux
echo "selinux is disabled." >> /tmp/deploy.log

systemctl restart nginx

}

main(){
    check_root
    create_ssh_user
    import_elk_repo
    install_nginx
    configuring_load_balancer
}

main