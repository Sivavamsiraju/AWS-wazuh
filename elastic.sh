#!/bin/bash
# Install Elastic data node using Cloudformation template

touch /tmp/deploy.log

echo "Elasticsearch: Starting process." > /tmp/deploy.log
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
yum install curl unzip wget libcap

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

echo "Added Elasticsearch repo." >> /tmp/deploy.log
}

install_elasticsearch(){
    echo "Installing Elasticsearch." >> /tmp/deploy.log
    # Installing Elasticsearch
    yum install opendistroforelasticsearch -y
    chkconfig --add elasticsearch
    echo "Installed Elasticsearch." >> /tmp/deploy.log
}

configuring_elasticsearch(){

#Elasticsearch configuration
curl -so /etc/elasticsearch/elasticsearch.yml https://packages.wazuh.com/resources/4.1/open-distro/elasticsearch/7.x/elasticsearch.yml
echo "Elasticsearch configuration file downloaded." >> /tmp/deploy.log

#Elasticsearch roles and users
curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles.yml https://packages.wazuh.com/resources/4.1/open-distro/elasticsearch/roles/roles.yml
curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/roles_mapping.yml https://packages.wazuh.com/resources/4.1/open-distro/elasticsearch/roles/roles_mapping.yml
curl -so /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/internal_users.yml https://packages.wazuh.com/resources/4.1/open-distro/elasticsearch/roles/internal_users.yml
echo "Elasticsearch users and roles files downloaded." >> /tmp/deploy.log

#Certificates creation and deployment
## remove default Certificates
rm /etc/elasticsearch/esnode-key.pem /etc/elasticsearch/esnode.pem /etc/elasticsearch/kirk-key.pem /etc/elasticsearch/kirk.pem /etc/elasticsearch/root-ca.pem -f

#Generate and deploy the certificates:
#Download the wazuh-cert-tool.sh to create the certificates
curl -so ~/wazuh-cert-tool.sh https://packages.wazuh.com/resources/4.1/open-distro/tools/certificate-utility/wazuh-cert-tool.sh
curl -so ~/instances.yml https://packages.wazuh.com/resources/4.1/open-distro/tools/certificate-utility/instances.yml

# Configuring instances data
cat > ~/instances.yml << EOF
# Elasticsearch nodes
elasticsearch-nodes:
  - name: node-1
    ip:
      - 192.168.1.163

# Wazuh server nodes
wazuh-servers:
  - name: master-node
    ip:
      - 192.168.1.189
  - name: worker-node
    ip:
      - 192.168.1.222

# Kibana node
kibana:
  - name: node-2
    ip:
      - 192.168.1.163
EOF

#Run the wazuh-cert-tool.sh to create the certificates
bash ~/wazuh-cert-tool.sh

#Replace elasticsearch-node-name with your Elasticsearch node name, the same used in instances.yml to create the certificates, and move the certificates to their corresponding location:
node_name=node-1

mkdir /etc/elasticsearch/certs/
mv ~/certs/$node_name* /etc/elasticsearch/certs/
mv ~/certs/admin* /etc/elasticsearch/certs/
cp ~/certs/root-ca* /etc/elasticsearch/certs/
mv /etc/elasticsearch/certs/$node_name.pem /etc/elasticsearch/certs/elasticsearch.pem
mv /etc/elasticsearch/certs/$node_name-key.pem /etc/elasticsearch/certs/elasticsearch-key.pem

# Compress all the necessary files to be sent to all the instances:
cd ~/certs/
tar -cvf certs.tar *=
mv ~/certs/certs.tar ~/

#Enable and start the Elasticsearch service:
systemctl daemon-reload
systemctl enable elasticsearch
systemctl start elasticsearch

#Run the Elasticsearch securityadmin script to load the new certificates information and start the cluster. To run this command, the value <elasticsearch_IP> must be replaced by the Elasticsearch installation IP
export JAVA_HOME=/usr/share/elasticsearch/jdk/ && /usr/share/elasticsearch/plugins/opendistro_security/tools/securityadmin.sh -cd /usr/share/elasticsearch/plugins/opendistro_security/securityconfig/ -nhnv -cacert /etc/elasticsearch/certs/root-ca.pem -cert /etc/elasticsearch/certs/admin.pem -key /etc/elasticsearch/certs/admin-key.pem -h 192.168.1.163

#allow port for elasticsearch from firewall
firewall-cmd --zone=public --permanent --add-port 9200/tcp
firewall-cmd --reload

# restarting elasticsearch after changes
start_elasticsearch
}

start_elasticsearch(){
    echo "start_elasticsearch." >> /tmp/deploy.log
    # Correct owner for Elasticsearch directories
    chown elasticsearch:elasticsearch -R /etc/elasticsearch
    chown elasticsearch:elasticsearch -R /usr/share/elasticsearch
    chown elasticsearch:elasticsearch -R /var/lib/elasticsearch
    systemctl daemon-reload
    # Starting Elasticsearch
    echo "daemon-reload." >> /tmp/deploy.log
    systemctl restart elasticsearch
    echo "done with starting elasticsearch service." >> /tmp/deploy.log
}

enable_elasticsearch(){
    echo "Enabling elasticsearch..." >> /tmp/deploy.log
    systemctl enable elasticsearch
    if [ $? -eq0 ]; then
        echo "Elasticsearch enabled." >> /tmp/deploy.log
    else
        echo "Could not enable Elasticsearch" >> /tmp/deploy.log
    fi
}

disable_elk_repos(){
    # Disable repositories
    sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/elastic.repo
}

install_kibana(){
  #install Kibana
  yum install opendistroforelasticsearch-kibana -y

}

configuring_kibana(){
curl -so /etc/kibana/kibana.yml https://packages.wazuh.com/resources/4.1/open-distro/kibana/7.x/kibana.yml
cat > /etc/kibana/kibana.yml << EOF
server.host: 192.168.1.163
elasticsearch.hosts: https://192.168.1.163:9200
server.port: 443
elasticsearch.ssl.verificationMode: certificate
elasticsearch.username: kibanaserver
elasticsearch.password: kibanaserver
elasticsearch.requestHeadersWhitelist: ["securitytenant","Authorization"]
opendistro_security.multitenancy.enabled: true
opendistro_security.readonly_mode.roles: ["kibana_read_only"]
server.ssl.enabled: true
server.ssl.key: "/etc/kibana/certs/kibana-key.pem"
server.ssl.certificate: "/etc/kibana/certs/kibana.pem"
elasticsearch.ssl.certificateAuthorities: ["/etc/kibana/certs/root-ca.pem"]
server.defaultRoute: /app/wazuh?security_tenant=global
EOF

# Create the /usr/share/kibana/data directory
mkdir /usr/share/kibana/data
chown -R kibana:kibana /usr/share/kibana/data

#Install the Wazuh Kibana plugin:
##The installation of the plugin must be done from the Kibana home directory:
cd /usr/share/kibana
sudo -u kibana bin/kibana-plugin install https://packages.wazuh.com/4.x/ui/kibana/wazuh_kibana-4.1.5_7.10.2-1.zip

#Replace kibana-node-name with your Kibana node name, the same used in instances.yml to create the certificates, and move the certificates to their corresponding location. This guide assumes that a copy of certs.tar, created during the Elasticsearch installation, has been placed in the root home folder (~/).
node_name=node-2

mkdir /etc/kibana/certs

mv ~/certs/$node_name* /etc/kibana/certs/
mv ~/certs/admin* /etc/kibana/certs/
cp ~/certs/root-ca* /etc/kibana/certs/
mv /etc/kibana/certs/$node_name.pem /etc/kibana/certs/kibana.pem
mv /etc/kibana/certs/$node_name-key.pem /etc/kibana/certs/kibana-key.pem

chmod 755 /etc/kibana/certs/*



#Link Kibana’s socket to privileged port 443:
setcap 'cap_net_bind_service=+ep' /usr/share/kibana/node/bin/node

#Enable and start the Kibana service:
systemctl daemon-reload
systemctl enable kibana
systemctl start kibana

#allow port for elasticsearch from firewall
firewall-cmd --zone=public --permanent --add-port 443/tcp
firewall-cmd --reload

}

main(){
    check_root
    create_ssh_user
    import_elk_repo
    install_elasticsearch
    configuring_elasticsearch
    enable_elasticsearch
    start_elasticsearch
    disable_elk_repos
    install_kibana
    configuring_kibana

}

main
