## RITA/Zeek Installer

#### Generated installer directory
```
rita-<version>.tar.gz
│   install_rita.yml
│   install_rita.sh
|   install_zeek.yml
|   install_pre.yml
│
└───/scripts
│    │   ansible-installer.sh
│    │   helper.sh
│    │   sshprep.sh
│    
└───/files
│   │   
│   │   rita-<version>-image.tar
│   │   docker-compose
│   │
│   └───/opt
│   │   │   docker-compose.yml
│   │   │   .env
│   │   │   README
│   │   │   LICENSE
│   │   │   rita.sh
|   |   |   zeek
│   │
│   └───/etc
│       │   config.hjson
│       │   config.xml
│       │   http_extensions_list.csv
│       │   logger-cron
│       │   syslog-ng.conf
│       │   timezone.xml
│       └───/threat_intel_feeds

```


### Generating an installer

Note: generating the installer on a branch that has no tag when running `git describe --always --abbrev=0 --tags` will generate a broken installer.

Run:
`./installer/generate_installer.sh`

The script will generate an installer tar file in the `installer` folder, named `rita-v<version number>-installer.tar.gz`.

Verify that all files in the above directory tree exist in the generated tar file.

Verify that all occurences of "REPLACE_ME" within scripts and/or playbooks got updated with the proper version number that is expected.
The version for RITA that gets replaced should match the current tag.

The version for Zeek that gets replaced should be the desired version of docker-zeek to be used in this release.

The docker-zeek repo pushes a built multi-architecture image of zeek to DockerHub using Github Actions. The generate_installer script should specify which tag version on [Dockerhub](https://hub.docker.com/r/activecm/zeek/tags) you wish to include with this release. Multi-architecture tags require all architectures to finish building before being merged into one tag, so if the build actions are in progress, please be patient and wait for them to finish before attempting to install it. 

### Running the installer
To install RITA on the current system, run:
`./rita-v<version>-installer/install_rita.sh localhost`.

To install RITA on a remote system, run:
`./rita-v<version>-installer/install_rita.sh root@8.8.8.8`.

### Updating the installer
Each file that is expected to be in the installer must be explicitly copied to the installer within the `./installer/generate_installer.sh` script. 

If any new Ansible playbook or script that uses the "REPLACE_ME" string to insert a version is added, the generate_installer script must be updated to replace that string with the proper version.

Any versions for RITA should NOT be hard-coded. The version should be retrieved by the generate_installer script automatically. The only hard-coded versions in the generator should be for external projects.


### "One-line installer"
To make installing both RITA and Zeek easier, a one-line installer is created and uploaded to the release artifacts on Github. This installer is generated with the generate_installer.sh script as well, but is uploaded to the release within the Generate Installer Github Action.
This one line installer is a single script (not a tar file). It installs RITA & Zeek on the local system and does NOT require passing any arguments to it.


### Zeek
There are multiple moving parts in order to build Zeek and include it in a RITA install bundle.

The main Zeek repo is [docker-zeek](https://github.com/activecm/docker-zeek). This repository contains the Dockerfile definition needed to build the docker image of Zeek that includes custom modifications like timeouts and the [zeek-open-connections](https://github.com/activecm/zeek-open-connections) plugin.

The docker-zeek repo is responsible for building the multi-arch image for Zeek in Github Actions. The actions automatically upload the image to Dockerhub. In order to test changes locally without uploading them to Dockerhub, the docker-zeek image must be built on your local system and tagged with a name that is NOT similar to `activecm/zeek:<any version>`. To test the zeek script with this custom-built image, the `zeek` script in the docker-zeek repo must be updated to use your custom tag instead of whatever is listed in the `IMAGE_NAME` variable.

The zeek-open-connections plugin must have an updated tag in order to be recognized by the Zeek package manager (zkg). Follow the instructions in that repo's README for more details.

The RITA installer includes an Ansible playbook that pulls the desired version of `activecm/zeek` from Dockerhub and creates the necessary directories needed to run Zeek. The installer generator also pulls the `zeek` script from the `docker-zeek` repo and includes it in the installer, along with listing the proper image version in the `IMAGE_NAME` variable. Aside from these two items, Zeek and RITA are independent of each other. 