# System Requirements

## Operating System

- ✅: Official Support
- ⚠️: Unofficial Support
- ❌: Unsupported

| OS              | Versions | Platform | Status | 
| :---------------- | :------ | :---- | :----: | 
| CentOS         | `9 Stream` | `amd64` | ✅ |
| Rocky         | `9` | `amd64` | ✅ |
| Ubuntu        |   `24.04`   | `amd64`| ✅ |
| Windows        |    | | ❌ |

## Hardware
- CPU: RITA uses parallel processing and benefits from more CPU cores.
- RAM: Larger datasets may require more memory.
- Storage: RITA's datasets are significantly smaller than the Zeek logs so storage requirements are minimal compared to retaining the Zeek log files.

### RITA
The following are recommended specs for different use cases. 
#### Casual Usage
* Processor - 4+ cores. 
* Memory - 16GB. 
* Storage - SSD or NVME (250GB+)

#### Production
 * Processor - 8+ cores.
 * Memory - 32GB
 * Storage - SSD or NVME (500GB+)
 
### Zeek (Production)
The following requirements apply to the Zeek system.

* Processor - Three cores plus an additional core for every 100 Mb of traffic being captured. This should be dedicated hardware, as resource congestion with other VMs can cause packets to be dropped or missed.
* Memory - 16GB minimum. 64GB+ if monitoring 100Mb or more of network traffic. 128GB+ if monitoring 1Gb or more of network traffic.
* Storage - 300GB minimum. 1TB+ is recommended to reduce log maintenance.
* Network - In order to capture traffic with Zeek, you will need at least 2 network interface cards (NICs). One will be for management of the system and the other will be the dedicated capture port.