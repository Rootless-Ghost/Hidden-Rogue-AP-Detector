# Hidden Rogue AP Detector

A Python-based tool for detecting rogue/unauthorized wireless access points on a network using RSSI signal strength analysis.

## Features

- **Rogue AP Detection**: Identifies unauthorized access points using a whitelist approach
- **Signal Strength Analysis**: Uses RSSI measurements to estimate AP location
- **Multiple Scanning Modes**:
  - Active scanning using `iwlist`
  - Passive scanning using packet sniffing with `scapy`
- **Alerting System**: Warns when new APs are detected with strong signal
- **GPS Integration**: Optional tracking of physical locations when detecting APs
- **Comprehensive Logging**: Detailed records of all detected networks

## Requirements

- Python 3.x
- `scapy` package
- `wireless-tools` package (for `iwlist`)
- `gpsd-py3` (optional, for GPS integration)
- Root privileges (required for monitor mode)

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/hidden-rogue-ap-detector.git
   cd hidden-rogue-ap-detector
   ```

2. Install the required Python packages:
   ```
   pip install scapy
   pip install gpsd-py3  # Optional, for GPS support
   ```

3. Install the wireless tools package:
   - On Debian/Ubuntu:
     ```
     sudo apt-get install wireless-tools
     ```
   - On CentOS/RHEL:
     ```
     sudo yum install wireless-tools
     ```
   - On macOS:
     ```
     brew install wireless-tools
     ```

## Usage

The script must be run with root privileges to enable monitor mode:

```
sudo python rogue_ap_detector.py [options]
```

### Command Line Options

```
  -h, --help            Show this help message and exit
  -i INTERFACE, --interface INTERFACE
                        Wireless interface to use (default: wlan0)
  -m {active,passive}, --mode {active,passive}
                        Scanning mode: active (iwlist) or passive (scapy sniffing)
  -t THRESHOLD, --threshold THRESHOLD
                        RSSI threshold for alerts in dBm (default: -65)
  -s SCAN_INTERVAL, --scan-interval SCAN_INTERVAL
                        Interval between scans in seconds (default: 30)
  -g, --gps             Enable GPS integration if available
  -w WHITELIST, --whitelist WHITELIST
                        Path to whitelist file (default: whitelist.json)
  -o OUTPUT, --output OUTPUT
                        Output file for results (default: detected_aps.json)
```

### Examples

Basic usage with default settings:
```
sudo python rogue_ap_detector.py
```

Using a specific interface with passive scanning:
```
sudo python rogue_ap_detector.py -i wlan1 -m passive
```

Enable GPS integration with a custom whitelist:
```
sudo python rogue_ap_detector.py -g -w my_whitelist.json
```

## Whitelist Management

The whitelist is a JSON file containing MAC addresses of authorized access points:

```json
{
    "authorized_aps": [
        "00:11:22:33:44:55",
        "AA:BB:CC:DD:EE:FF"
    ]
}
```

You can manually edit this file, or use the script's API to manage the whitelist programmatically.

## How it Works

1. **Scanning**: The tool scans for wireless networks using either:
   - Active scanning via `iwlist` commands (non-intrusive but less detailed)
   - Passive scanning by capturing beacon frames with `scapy` (requires monitor mode)

2. **Detection**: Each detected AP is compared against the whitelist. Unrecognized APs are flagged as potential rogues.

3. **Analysis**: Signal strength measurements (RSSI) are used to approximate the physical location of the detected APs.

4. **Alerting**: When a rogue AP with strong signal is detected, an alert is triggered.

## Extending the Tool

### Adding Different Alert Methods

You can extend the `_alert_rogue_ap` method to implement different alerting mechanisms:

- Email notifications
- SMS alerts
- Integration with security systems
- Push notifications

### Improving Location Accuracy

For better location triangulation:
- Implement a more sophisticated algorithm using multiple readings from different locations
- Integrate with more precise positioning systems
- Add support for signal strength heat maps

## Security Considerations

- The tool should be used only on networks you own or have explicit permission to test
- Be aware that putting wireless interfaces in monitor mode can affect normal network connectivity
- Maintain your whitelist regularly to avoid false positives

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- The `scapy` project for packet manipulation capabilities
- The wireless tools package for network scanning functionality
