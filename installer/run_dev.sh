set -e
droplet_ip="$1"
if [ -z "$droplet_ip" ]; then
    echo "droplet ip was not provided"
    exit 1
fi

VERSION=$(git describe --always --abbrev=0 --tags)


./generate_installer.sh
tar -xf rita-${VERSION}.tar.gz
./rita-${VERSION}-installer/install_rita.sh "root@$droplet_ip"


# # # # ansible-playbook -i digitalocean_inventory.py -e "install_hosts=${droplet_ip}" "./rita-${VERSION}-installer/install_rita.yml"




# copy over test data
scp -r ../test_data/open_sni "root@$droplet_ip":/root/sample_logs

# # copy over test script
scp ./test_installed.sh "root@$droplet_ip":/root/test_installed.sh

# run test script
ssh -t "root@$droplet_ip" /root/test_installed.sh "$VERSION"
# 