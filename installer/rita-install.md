
#ansible install playbook for rita V2.

#sample runs:
#	Optional: Add the following block, without #'s  to /etc/ansible/hosts (or /opt/local/etc/ansible/hosts if using ansible on mac with mac ports).
#The hosts must each be on their own line.  These can be full or short hostnames or a name following "Host" in ~/.ssh/config .
#
#[allritas]
#ro810
#ub2404
#
#	Then run this, with a comma separated list of hostnames from the above file with a comma at the end of the list:
#
#	ansible-playbook -C -K -i "ro810,ub2404," -e "install_hosts=ro810,ub2404," ~/.ansible/playbooks/rita-install.yml | grep -v '^skipping: '	#-C (no changes) means do a dry run
#	ansible-playbook -K -i "ro810,ub2404," -e "install_hosts=ro810,ub2404," ~/.ansible/playbooks/rita-install.yml | grep -v '^skipping: '



#Many thanks to but-i-am-dominator for his help with this playbook.

#Intended supported distributions.  These have had testing done on at least one version.
#ADHD: 4 (based on ubuntu 20, works)
#AlmaLinux: 8, 9 (tested: 9.4, works)
#CentOS: stream 9 (tested: stream 9, works)
#Debian: 11, 12 (tested: debian 12, works)
#Fedora: 39, 40 (tested: fedora 40, works)
#Kali: 2024.2 (tested: 2024.2, works)
#OracleLinux: 9 (tested: 9.4, works.  NOTE: this was done on Security Onion 2.4.70 which is _based_ on Oracle Linux 9.4)
#Rocky: 8, 9 (tested: rocky 8, works)
#Security Onion: 2.4.70 (based on oracle linux 9, works)
#Ubuntu 20.04, 22.04, 24.04 (tested: ubuntu 24.04, works)

#We hope to support these in the future, but they are not supported at the moment.
#MacOS: Sonoma
#RHEL: 8, 9 (as of 20240618 there's a known conflict between rhel 9 and docker-ce:
#Note: RHEL 9 is currently (20240618) broken with docker-ce (and docker knows this
#and puts up a warning for this distro.  Current error from trying to install on rhel 9:
#
#fatal: [rhel9-aws]: FAILED! => {"changed": false, "failures": [],
#"msg": "Depsolve Error occurred: \n Problem 1: cannot install the
#best candidate for the job\n  - nothing provides container-selinux
#>= 2:2.74 needed by docker-ce-3:26.1.4-1.el9.x86_64 from
#docker-ce\n  - nothing provides iptables needed by
#docker-ce-3:26.1.4-1.el9.x86_64 from docker-ce\n Problem 2: cannot
#install the best candidate for the job\n  - nothing provides
#container-selinux >= 2:2.74 needed by
#containerd.io-1.6.33-3.1.el9.x86_64 from docker-ce", "rc": 1,
#"results": []}

#Intended supported CPU architectures - not all have been tested yet.  For any CPU architectures we hope to support, we need
#to build rita for that architecture.  To confirm whether your CPU is 32 bit vs 64 bit, run
#lshw | head | grep -i width
#    width: 64 bits
#
#x86_64		#All testing so far has been on x86_64
#Possible future supported architectures
#aarch64	#Pi4 and Pi5, but note this requires a 64 bit OS like Ubuntu or recent RaspiOS64 for pi.  Appears to be equal to arm64.
#armhf		#32 bit arm, likely includes pi3 and below (or pi4 and pi5 when running a 32 bit OS)
#		#For reference, pi zero and pi1 are 32 bit/arm6hf, pi2 is 32 bit/armhf, and (64 bit) pi zero 2, pi3, and pi4 are arm64=aarch64 (though these may not have a 64 bit os to run on them.)







