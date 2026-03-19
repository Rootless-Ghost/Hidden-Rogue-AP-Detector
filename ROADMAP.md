# Hidden Rogue AP Detector Roadmap

This document outlines the planned features and improvements for future releases.

Features are planned but not guaranteed — contributions welcome.

## Short-term Goals (v1.1.0)

- Add email/SMS alerting for rogue AP detection
- Implement automatic whitelist learning mode
- Add support for multiple wireless interfaces
- Improve RSSI-based location estimation accuracy
- Add CSV export option alongside JSON

## Medium-term Goals (v1.2.0 - v1.3.0)

- Create a web dashboard for real-time monitoring
- Implement signal strength heatmap generation
- Add multi-point triangulation for AP location
- Develop historical trend analysis for detected APs
- Add integration with SIEM platforms (ELK Stack, Wazuh)
- Implement PCAP capture for rogue AP traffic

## Long-term Goals (v2.0.0+)

- Develop a full GUI application
- Add machine learning for anomaly detection
- Implement distributed sensor support for enterprise environments
- Create API for integration with other security tools
- Add support for 802.11ax (Wi-Fi 6) specific detection
- Develop automated incident response actions

## Completed

- Initial release with core functionality (v1.0.0)
- Whitelist-based rogue AP detection
- Active and passive scanning modes
- RSSI signal strength analysis
- GPS integration support
- JSON output and logging
