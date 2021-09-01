#!/bin/bash
# Install Elastic data node using Cloudformation template

touch /tmp/deploy.log

echo "Wazuh-Manager: Starting process." > /tmp/deploy.log
ssh_username="wazuh_elastic"
ssh_password="2021"
elastic_version=7.11.2
wazuh_version=4.1.5
eth0_ip=$(hostname -I |  head -1 | cut -d' ' -f1)
elastic_major_version=$(echo ${elastic_version} | cut -d'.' -f1)
wazuh_major=`echo $wazuh_version | cut -d'.' -f1`
wazuh_minor=`echo $wazuh_version | cut -d'.' -f2`
wazuh_patch=`echo $wazuh_version | cut -d'.' -f3`
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

import_elk_repo(){
#Install dependencies
yum install curl

# Configuring Elastic repository
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

#add wazuh repo to OS
cat > /etc/yum.repos.d/wazuh.repo << EOF
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

echo "Added Wazuh repo." >> /tmp/deploy.log
}

install_wazuh(){
    #Installing the Wazuh manager
    yum install wazuh-manager

    echo "Installed Wazuh Manager" >> /tmp/deploy.log

}

install_filebeat(){
    #Installing Filebeat
    #Filebeat installation and configuration
    yum install filebeat
    curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/resources/4.1/open-distro/filebeat/7.x/filebeat.yml
    curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/4.1/extensions/elasticsearch/7.x/wazuh-template.json
    chmod go+r /etc/filebeat/wazuh-template.json
    curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.1.tar.gz | tar -xvz -C /usr/share/filebeat/module

    cat > /etc/filebeat/filebeat.yml << EOF
# Wazuh - Filebeat configuration file
output.elasticsearch:
  hosts: ["192.168.1.163:9200"]
  protocol: https
  username: "admin"
  password: "admin"
  ssl.certificate_authorities:
    - /etc/filebeat/certs/root-ca.pem
  ssl.certificate: "/etc/filebeat/certs/filebeat.pem"
  ssl.key: "/etc/filebeat/certs/filebeat-key.pem"
setup.template.json.enabled: true
setup.template.json.path: '/etc/filebeat/wazuh-template.json'
setup.template.json.name: 'wazuh'
setup.ilm.overwrite: true
setup.ilm.enabled: false

filebeat.modules:
  - module: wazuh
    alerts:
      enabled: true
    archives:
      enabled: false
EOF
}

configuring_wazuh(){
    #Key that is used to encrypt communication between cluster nodes
    openssl rand -hex 16 > cluster_key.txt

    node_name=master-node
    mkdir /etc/filebeat/certs

    # install epel
    yum search epel-release
    yum info epel-release
    yum install epel-release

    #install sshpass
    yum install -y sshpass

    #File Transfering
    sshpass -f $ssh_password scp -o "StrictHostKeyChecking=no" $ssh_username@192.168.1.204:/home/$ssh_username/certs/certs.tar /home/$ssh_username/

    mv ~/certs.tar /etc/filebeat/certs/
    cd /etc/filebeat/certs/
    tar -xf certs.tar $node_name.pem $node_name-key.pem root-ca.pem
    mv /etc/filebeat/certs/$node_name.pem /etc/filebeat/certs/filebeat.pem
    mv /etc/filebeat/certs/$node_name-key.pem /etc/filebeat/certs/filebeat-key.pem
    cd

    systemctl daemon-reload
    systemctl enable filebeat
    systemctl start filebeat
}

cluster_configuration(){
    cluster_key = `cat cluster_key.txt`
    sed -i -e "s#<node_name>node01</node_name>#<node_name>master-node</node_name>#" /var/ossec/etc/ossec.conf
    sed -i -e "s#<bind_addr>0.0.0.0</bind_addr>#<bind_addr>192.168.1.205</bind_addr>#" /var/ossec/etc/ossec.conf
    sed -i -e "s#<node>NODE_IP</node>#<node>192.168.1.205</node>#" /var/ossec/etc/ossec.conf
    sed -i -e "s#<disabled>yes</disabled>#<disabled>no</disabled>#" /var/ossec/etc/ossec.conf
    sed -i -e "s#<key></key>#<key>$cluster_key</key>#" /var/ossec/etc/ossec.conf

    systemctl daemon-reload
    systemctl enable wazuh-manager
    systemctl start wazuh-manager

    #allow port for elasticsearch from firewall
    firewall-cmd --zone=public --permanent --add-port 1516/tcp
    firewall-cmd --reload

}

main(){
    check_root
    create_ssh_user
    import_wazuh_repo
    install_wazuh
    install_filebeat
    configuring_wazuh
    cluster_configuration
}

main