# RITA (Real Intelligence Threat Analytics)

[![RITA Logo](rita-logo.png)](https://www.activecountermeasures.com/free-tools/rita/)

If you get value out of RITA and would like to go a step further with hunting automation, futuristic visualizations, and data enrichment, then take a look at [AC-Hunter](https://www.activecountermeasures.com/).

Sponsored by [Active Countermeasures](https://activecountermeasures.com/).

---

RITA is an open source framework for network traffic analysis.

The framework ingests [Zeek Logs](https://www.zeek.org/) in TSV or JSON format, and currently supports the following major features:
 - **Beaconing Detection**: Search for signs of beaconing behavior in and out of your network
- **Long Connection Detection**: Easily see connections that have communicated for long periods of time
 - **DNS Tunneling Detection**: Search for signs of DNS based covert channels
 - **Threat Intel Feed Checking**: Query threat intel feeds to search for suspicious domains and hosts

 ## Quick Start
 Please see our recommended [System Requirements](docs/System%20Requirements.md).

1. Download the [RITA Installer](https://github.com/activecm/rita/releases) for the desired version.

2. Uncompress the installer tarfile.
   ```
   tar -xf rita-<version>-installer.tar.gz
   ```
3. Run the install script. 
   ```
   ./rita-<version>-installer/install_rita.sh <hosts to install on>
   ```
   To install RITA on the local system, pass `localhost` to the installer.
   To install RITA on one or more remote systems, pass a comma separated list of IPs or `user@ip` or FQDNs to the installer.
   For example:
   ```
   ./rita-<version>-installer/install_rita.sh "root@4.4.4.4,8.8.8.8,mydomain.com"
   ```


### Supported Platforms
- ✅: Official Support
- ⚠️: Unofficial Support
- ❌: Unsupported

| OS              | Versions | Platform | Status | 
| :---------------- | :------ | :---- | :----: | 
| CentOS         | `9 Stream` | `amd64` | ✅ |
| Rocky         | `9` | `amd64` | ✅ |
| Ubuntu        |   `24.04`   | `amd64`| ✅ |
| Windows        |    | | ❌ |
<!-- TODO: eventually add support -->
<!-- | MacOS        |   `Sonoma`   | `intel\|arm` | ✅ | -->

## Installing Zeek
If you do not already have Zeek installed, it can be installed from [docker-zeek](https://github.com/activecm/docker-zeek).

```
sudo wget -O /usr/local/bin/zeek https://raw.githubusercontent.com/activecm/docker-zeek/master/zeek

sudo chmod +x /usr/local/bin/zeek

zeek start
```

## Importing
Import data into RITA using the `import` command:
```
rita import --database=mydatabase --logs=~/mylogs
```

`database` is what you would like to name the dataset

`logs` is the path to the Zeek logs you wish to import

For datasets that should accumulate data over time, with the logs containing network info that is current (less than 24 hours old), use the `--rolling` flag during creation and each subsequent import into the dataset. The most common use case for this is importing logs from the a Zeek sensor on a cron job each hour.

Note: For datasets that contain over 24 hours of logs, but are over 24 hours old, simply import the top-level directory of the set of logs **without** the `--rolling` flag. Importing these logs with the `--rolling` flag may result in incorrect results.

To destroy and recreate a dataset, use the `--rebuild` flag.

## Configuration
See [Configuration](/docs/Configuration.md) for details on adjusting scoring.

## Searching

RITA follows a GitHub-style search syntax. Each field follows the `<field>:<value>` format, with each search criteria separated by a space. 
For example: 
```
src:192.168.88.2 dst:165.227.88.15 beacon:>=90 sort:duration-desc
```

### Supported Search Fields

| Column              | Field | Operators | Data Type |
| :---------------- | :------ | :---- | :---- |
| Severity        |   `severity`   |  | `critical\|high\|medium\|low` |
| Source           |   `src`   |  | IP address |
| Destination           |   `dst`   |  | IP address, FQDN |
| Beacon Score           |   `beacon`   | `>, >=, <, <=` | whole number
| Duration    |  `duration`   | `>, >=, <, <=` | string, ex:(`2h45m`)
| Subdomains |  `subdomains`   | `>, >=, <, <=` | whole number |
| Threat Intel |  `threat_intel`   | | `true\|false` |

### Supported Sort Fields
The sort syntax is `sort:<column>-<sort direction>`, with the sort direction being `asc` for ascending or `desc` for descending.

Supported Columns:

- severity
- beacon
- duration
- subdomains

## CSV Output
To output the results to CSV instead of viewing them within the terminal UI, pass the `--stdout` or `-o` flag to the `view` command:

*The flag must be before the name of the dataset.*
```
rita view --stdout mydataset
```

## Terminal UI Color Support
The terminal UI (TUI) supports colorful output by default. It does not need to be enabled. 

Check the value of the `"$TERM"` variable, this should be `xterm-256color`. If it is not, please set this variable in your OS's version of a `~/.bash_profile`, `~/.profile`, etc.

Depending on the color theme of your terminal, the TUI will adjust to either a light mode or a dark mode.

If you're really fancy and like pretty colors, consider using the [Catpuccin](https://catppuccin.com/ports?q=terminal) theme!