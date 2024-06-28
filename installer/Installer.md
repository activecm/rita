```
rita-<version>.tar.gz
│   install_rita.yml
│   install_rita.sh
│
└───/scripts
│    │   ansible-installer.sh
│    │   helper.sh
│    │   sshprep
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