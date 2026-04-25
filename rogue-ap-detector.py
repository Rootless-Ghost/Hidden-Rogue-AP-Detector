#!/usr/bin/env python3
"""
Hidden Rogue AP Detector

This script monitors for unauthorized/rogue access points on a wireless network.
It uses signal strength analysis (RSSI) to detect and potentially locate rogue APs.

Features:
- Continuous scanning for wireless networks
- Whitelist-based detection of unauthorized APs
- RSSI signal strength analysis for approximate location detection
- Alerting system for new AP detection
- Optional GPS integration for location tracking
- Logging of all detected access points

Requirements:
- Python 3.x
- scapy
- wireless-tools package (for iwlist)
- Optional: gpsd-py3 (for GPS integration)

Usage:
sudo python rogue_ap_detector.py

Note: Requires root privileges to put wireless interface in monitor mode
"""

import os
import sys
import time
import json
import logging
import argparse
import subprocess
from datetime import datetime
from threading import Thread
from typing import Dict, List, Optional, Set, Tuple
import hashlib

try:
    from scapy.all import Dot11, Dot11Beacon, Dot11Elt, sniff
    from scapy.layers.dot11 import Dot11ProbeResp
except ImportError:
    print("Error: Scapy package not found. Install it using 'pip install scapy'")
    sys.exit(1)

# Optional GPS support
GPS_AVAILABLE = False
try:
    import gpsd
    GPS_AVAILABLE = True
except ImportError:
    pass

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("rogue_ap_detector.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class RogueAPDetector:
    """Main class for detecting rogue access points"""
    
    def _mac_fingerprint(self, mac_address: str) -> str:
        """
        Return a short, non-reversible fingerprint of a MAC address for logging.

        This helps avoid logging the raw MAC address while still allowing
        correlation of log messages referring to the same address.
        """
        if not mac_address:
            return "unknown"
        digest = hashlib.sha256(mac_address.encode("utf-8")).hexdigest()
        return digest[:8]
    
    def __init__(self, interface: str, whitelist_file: str = "whitelist.json", 
                 scan_interval: int = 30, use_gps: bool = False,
                 alert_threshold: int = -65):
        """
        Initialize the Rogue AP Detector
        
        Args:
            interface: Wireless interface to use for scanning
            whitelist_file: Path to JSON file containing whitelisted APs
            scan_interval: Time in seconds between scans
            use_gps: Whether to use GPS for location tracking
            alert_threshold: RSSI threshold for alerting (stronger signals are more concerning)
        """
        self.interface = interface
        self.whitelist_file = whitelist_file
        self.scan_interval = scan_interval
        self.use_gps = use_gps and GPS_AVAILABLE
        self.alert_threshold = alert_threshold
        
        # Dictionary to store all detected APs: MAC -> {details}
        self.detected_aps = {}
        
        # Load whitelist
        self.whitelist = self._load_whitelist()
        
        # Initialize GPS if needed
        if self.use_gps:
            self._init_gps()
    
    def _init_gps(self) -> None:
        """Initialize the GPS connection"""
        try:
            gpsd.connect()
            logger.info("GPS initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize GPS: {e}")
            self.use_gps = False
    
    def _load_whitelist(self) -> Set[str]:
        """Load the whitelist of authorized APs from JSON file"""
        whitelist = set()
        try:
            if os.path.exists(self.whitelist_file):
                with open(self.whitelist_file, 'r') as f:
                    data = json.load(f)
                    # Convert all MAC addresses to uppercase for consistency
                    whitelist = {mac.upper() for mac in data.get('authorized_aps', [])}
                logger.info(f"Loaded {len(whitelist)} authorized APs from whitelist")
            else:
                logger.warning(f"Whitelist file {self.whitelist_file} not found. Creating empty whitelist.")
                self._save_whitelist(whitelist)
        except Exception as e:
            logger.error(f"Error loading whitelist: {e}")
        
        return whitelist
    
    def _save_whitelist(self, whitelist: Set[str]) -> None:
        """Save the whitelist to the JSON file"""
        try:
            with open(self.whitelist_file, 'w') as f:
                json.dump({'authorized_aps': list(whitelist)}, f, indent=4)
            logger.info(f"Saved {len(whitelist)} authorized APs to whitelist")
        except Exception as e:
            logger.error(f"Error saving whitelist: {e}")
    
    def add_to_whitelist(self, mac_address: str) -> None:
        """Add an AP to the whitelist"""
        mac_address = mac_address.upper()
        self.whitelist.add(mac_address)
        self._save_whitelist(self.whitelist)
        logger.info(
            "Added MAC address to whitelist (id=%s)",
            self._mac_fingerprint(mac_address),
        )
    
    def remove_from_whitelist(self, mac_address: str) -> None:
        """Remove an AP from the whitelist"""
        mac_address = mac_address.upper()
        if mac_address in self.whitelist:
            self.whitelist.remove(mac_address)
            self._save_whitelist(self.whitelist)
            logger.info(
                "Removed MAC address from whitelist (id=%s)",
                self._mac_fingerprint(mac_address),
            )
        else:
            logger.warning(
                "MAC address not found in whitelist (id=%s)",
                self._mac_fingerprint(mac_address),
            )
    
    def get_gps_location(self) -> Optional[Tuple[float, float]]:
        """Get current GPS coordinates if available"""
        if not self.use_gps:
            return None
        
        try:
            packet = gpsd.get_current()
            if packet.mode >= 2:  # 2D or 3D fix
                return (packet.lat, packet.lon)
        except Exception as e:
            logger.error(f"Error getting GPS location: {e}")
        
        return None
    
    def set_monitor_mode(self) -> bool:
        """Set the wireless interface to monitor mode"""
        try:
            # First, check if interface exists
            result = subprocess.run(['iwconfig', self.interface], 
                                   capture_output=True, text=True)
            if result.returncode != 0:
                logger.error(f"Interface {self.interface} not found")
                return False
            
            # Check if already in monitor mode
            if "Mode:Monitor" in result.stdout:
                logger.info(f"Interface {self.interface} already in monitor mode")
                return True
            
            # Bring down interface
            subprocess.run(['ifconfig', self.interface, 'down'], check=True)
            
            # Set monitor mode
            subprocess.run(['iwconfig', self.interface, 'mode', 'monitor'], check=True)
            
            # Bring interface back up
            subprocess.run(['ifconfig', self.interface, 'up'], check=True)
            
            logger.info(f"Set {self.interface} to monitor mode")
            return True
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to set monitor mode: {e}")
            return False
    
    def restore_managed_mode(self) -> None:
        """Restore the wireless interface to managed mode"""
        try:
            # Bring down interface
            subprocess.run(['ifconfig', self.interface, 'down'])
            
            # Set managed mode
            subprocess.run(['iwconfig', self.interface, 'mode', 'managed'])
            
            # Bring interface back up
            subprocess.run(['ifconfig', self.interface, 'up'])
            
            logger.info(f"Restored {self.interface} to managed mode")
        except subprocess.SubprocessError as e:
            logger.error(f"Failed to restore managed mode: {e}")
    
    def _extract_ssid(self, packet) -> Optional[str]:
        """Extract SSID from a beacon packet"""
        if packet.haslayer(Dot11Elt) and packet[Dot11Elt].ID == 0:
            return packet[Dot11Elt].info.decode('utf-8', errors='replace')
        return None
    
    def _calculate_signal_strength(self, packet) -> int:
        """Extract and calculate signal strength (RSSI) from packet"""
        try:
            # This field may vary depending on the version of scapy and the OS
            if hasattr(packet, 'dBm_AntSignal'):
                return packet.dBm_AntSignal
            elif hasattr(packet, 'signal_dbm'):
                return packet.signal_dbm
            # Extract from RadioTap header if available
            elif packet.haslayer('RadioTap'):
                return -(256-packet[RadioTap].dBm_AntSignal)
            # Default to a very weak signal if we can't determine it
            return -100
        except Exception:
            return -100
    
    def _packet_handler(self, packet) -> None:
        """Process each packet captured by scapy"""
        # Check if it's a beacon or probe response packet with the Dot11 layer
        if not (packet.haslayer(Dot11) and 
                (packet.haslayer(Dot11Beacon) or packet.haslayer(Dot11ProbeResp))):
            return
        
        # Extract AP details
        bssid = packet[Dot11].addr2
        if not bssid:
            return
        
        # Convert BSSID (MAC) to uppercase for consistency
        bssid = bssid.upper()
        ssid = self._extract_ssid(packet)
        signal_strength = self._calculate_signal_strength(packet)
        channel = None
        
        # Try to extract the channel
        for element in packet:
            # Check if it's a Dot11Elt element with ID 3 (DS Parameter Set - Channel)
            if element.haslayer(Dot11Elt) and element[Dot11Elt].ID == 3:
                channel = ord(element[Dot11Elt].info)
                break
        
        # Only process if we have all the required information
        if not ssid:
            return
        
        # Get current time and location
        timestamp = datetime.now().isoformat()
        location = self.get_gps_location() if self.use_gps else None
        
        # Update or create AP entry
        if bssid in self.detected_aps:
            # Update existing AP details
            self.detected_aps[bssid]['last_seen'] = timestamp
            self.detected_aps[bssid]['rssi_history'].append((timestamp, signal_strength))
            # Keep only the last 10 RSSI readings
            if len(self.detected_aps[bssid]['rssi_history']) > 10:
                self.detected_aps[bssid]['rssi_history'].pop(0)
            # Update location if using GPS
            if location:
                self.detected_aps[bssid]['location_history'].append((timestamp, location))
        else:
            # Create new AP entry
            self.detected_aps[bssid] = {
                'ssid': ssid,
                'channel': channel,
                'first_seen': timestamp,
                'last_seen': timestamp,
                'rssi_history': [(timestamp, signal_strength)],
                'location_history': [(timestamp, location)] if location else [],
                'is_authorized': bssid in self.whitelist
            }
            
            # Alert for new unauthorized APs
            if bssid not in self.whitelist and signal_strength > self.alert_threshold:
                self._alert_rogue_ap(bssid, ssid, signal_strength, channel)
    
    def _alert_rogue_ap(self, bssid: str, ssid: str, 
                        signal_strength: int, channel: Optional[int]) -> None:
        """Alert when a rogue AP is detected"""
        logger.warning(f"⚠️ ROGUE AP DETECTED ⚠️")
        logger.warning(f"BSSID: {bssid} | SSID: {ssid} | Signal: {signal_strength} dBm | Channel: {channel}")
        
        # Here you could implement additional alerting methods:
        # - Send email
        # - Send SMS
        # - Push notification
        # - Trigger system alert
        
        # For example, to send an email alert (requires additional setup):
        # self._send_email_alert(bssid, ssid, signal_strength, channel)
    
    def scan_networks(self) -> None:
        """Scan for wireless networks using iwlist"""
        try:
            # Run the iwlist scan command
            result = subprocess.run(['iwlist', self.interface, 'scan'], 
                                   capture_output=True, text=True)
            
            if result.returncode != 0:
                logger.error(f"iwlist scan failed: {result.stderr}")
                return
            
            # Process the output (simplified - actual parsing would be more complex)
            output = result.stdout
            cells = output.split('Cell ')
            
            for cell in cells[1:]:  # Skip the first element (header)
                lines = cell.split('\n')
                bssid = None
                ssid = None
                channel = None
                signal = None
                
                for line in lines:
                    line = line.strip()
                    if 'Address:' in line:
                        bssid = line.split('Address:')[1].strip().upper()
                    elif 'ESSID:' in line:
                        ssid = line.split('ESSID:')[1].strip('"')
                    elif 'Channel:' in line:
                        try:
                            channel = int(line.split('Channel:')[1].strip())
                        except ValueError:
                            pass
                    elif 'Signal level=' in line:
                        try:
                            signal_part = line.split('Signal level=')[1].split()[0]
                            # Handle different formats
                            if 'dBm' in signal_part:
                                signal = int(signal_part.split('dBm')[0])
                            else:
                                # Convert percentage to dBm (approximation)
                                percent = int(signal_part.split('/')[0])
                                signal = -100 + percent / 2
                        except (ValueError, IndexError):
                            pass
                
                if bssid and ssid:
                    timestamp = datetime.now().isoformat()
                    location = self.get_gps_location() if self.use_gps else None
                    
                    # Update or create AP entry (similar to packet handler logic)
                    if bssid in self.detected_aps:
                        self.detected_aps[bssid]['last_seen'] = timestamp
                        if signal is not None:
                            self.detected_aps[bssid]['rssi_history'].append((timestamp, signal))
                        if location:
                            self.detected_aps[bssid]['location_history'].append((timestamp, location))
                    else:
                        self.detected_aps[bssid] = {
                            'ssid': ssid,
                            'channel': channel,
                            'first_seen': timestamp,
                            'last_seen': timestamp,
                            'rssi_history': [(timestamp, signal)] if signal is not None else [],
                            'location_history': [(timestamp, location)] if location else [],
                            'is_authorized': bssid in self.whitelist
                        }
                        
                        # Alert for new unauthorized APs with strong signal
                        if bssid not in self.whitelist and signal is not None and signal > self.alert_threshold:
                            self._alert_rogue_ap(bssid, ssid, signal, channel)
        
        except Exception as e:
            logger.error(f"Error scanning networks: {e}")
    
    def continuous_passive_scan(self) -> None:
        """Continuously scan for beacons using scapy"""
        logger.info(f"Starting passive scanning on interface {self.interface}")
        
        try:
            # Monitor mode is required for this type of scanning
            if not self.set_monitor_mode():
                logger.error("Failed to set monitor mode, cannot perform passive scanning")
                return
            
            # Start capturing packets
            sniff(iface=self.interface, prn=self._packet_handler, store=0)
        except KeyboardInterrupt:
            logger.info("Passive scanning stopped by user")
        except Exception as e:
            logger.error(f"Error during passive scanning: {e}")
        finally:
            # Restore managed mode
            self.restore_managed_mode()
    
    def start_periodic_scanning(self) -> None:
        """Start periodic active scanning using iwlist"""
        logger.info(f"Starting periodic scanning every {self.scan_interval} seconds")
        
        try:
            while True:
                logger.info("Performing network scan...")
                self.scan_networks()
                self.print_detected_aps()
                time.sleep(self.scan_interval)
        except KeyboardInterrupt:
            logger.info("Periodic scanning stopped by user")
        except Exception as e:
            logger.error(f"Error during periodic scanning: {e}")
    
    def estimate_ap_location(self, bssid: str) -> Optional[str]:
        """
        Estimate AP location based on signal strength readings
        Returns a string with a rough location estimate
        """
        if bssid not in self.detected_aps:
            return None
        
        ap = self.detected_aps[bssid]
        
        # If we have GPS data, use it
        if self.use_gps and ap['location_history']:
            # Simple approach: use the location with strongest signal
            strongest_signal = -100
            best_location = None
            
            for entry in ap['rssi_history']:
                timestamp, signal = entry
                # Find matching timestamp in location history
                for loc_entry in ap['location_history']:
                    loc_timestamp, location = loc_entry
                    if loc_timestamp == timestamp and signal > strongest_signal:
                        strongest_signal = signal
                        best_location = location
            
            if best_location:
                return f"Approximately at coordinates: {best_location[0]:.6f}, {best_location[1]:.6f}"
        
        # If no GPS or no match, estimate based on signal strength
        if ap['rssi_history']:
            # Get the most recent signal strength
            latest_signal = ap['rssi_history'][-1][1]
            
            # Very rough estimate based on signal strength
            if latest_signal > -50:
                return "Very close (likely within 10 meters)"
            elif latest_signal > -65:
                return "Nearby (likely within 20-30 meters)"
            elif latest_signal > -75:
                return "In the general vicinity (likely within 40-60 meters)"
            else:
                return "Far away (likely over 60 meters away)"
        
        return "Unable to estimate location"
    
    def print_detected_aps(self) -> None:
        """Print a summary of all detected APs"""
        print("\n" + "="*80)
        print(f"DETECTED ACCESS POINTS: {len(self.detected_aps)}")
        print("="*80)
        print(f"{'BSSID':<18} {'SSID':<20} {'Channel':<8} {'Signal':<8} {'Status':<12} {'Location Est.'}")
        print("-"*80)
        
        for bssid, ap in sorted(self.detected_aps.items()):
            # Get the most recent signal strength
            latest_signal = ap['rssi_history'][-1][1] if ap['rssi_history'] else 'N/A'
            
            # Determine status
            status = "AUTHORIZED" if ap['is_authorized'] else "⚠️ ROGUE ⚠️"
            
            # Estimate location
            location = self.estimate_ap_location(bssid)
            if not location:
                location = "Unknown"
            
            print(f"{bssid:<18} {ap['ssid']:<20} {ap['channel']:<8} {latest_signal:<8} {status:<12} {location}")
        
        print("="*80)
    
    def save_results(self, filename: str = "detected_aps.json") -> None:
        """Save detected APs to a JSON file"""
        try:
            with open(filename, 'w') as f:
                json.dump(self.detected_aps, f, indent=4)
            logger.info(f"Saved results to {filename}")
        except Exception as e:
            logger.error(f"Error saving results: {e}")
    
    def run(self, mode: str = "active") -> None:
        """
        Run the detector in the specified mode
        
        Args:
            mode: 'active' for periodic iwlist scanning, 'passive' for continuous sniffing
        """
        try:
            if mode == "passive":
                self.continuous_passive_scan()
            else:
                self.start_periodic_scanning()
        except KeyboardInterrupt:
            logger.info("Detector stopped by user")
        finally:
            # Save results before exiting
            self.save_results()


def main():
    """Main function to parse arguments and start the detector"""
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Hidden Rogue AP Detector")
    parser.add_argument("-i", "--interface", default="wlan0", 
                        help="Wireless interface to use (default: wlan0)")
    parser.add_argument("-m", "--mode", choices=["active", "passive"], default="active",
                        help="Scanning mode: active (iwlist) or passive (scapy sniffing)")
    parser.add_argument("-t", "--threshold", type=int, default=-65,
                        help="RSSI threshold for alerts in dBm (default: -65)")
    parser.add_argument("-s", "--scan-interval", type=int, default=30,
                        help="Interval between scans in seconds (default: 30)")
    parser.add_argument("-g", "--gps", action="store_true",
                        help="Enable GPS integration if available")
    parser.add_argument("-w", "--whitelist", default="whitelist.json",
                        help="Path to whitelist file (default: whitelist.json)")
    parser.add_argument("-o", "--output", default="detected_aps.json",
                        help="Output file for results (default: detected_aps.json)")
    
    args = parser.parse_args()
    
    # Check for root privileges
    if os.geteuid() != 0:
        print("Error: This script must be run as root")
        sys.exit(1)
    
    # Create and run the detector
    try:
        detector = RogueAPDetector(
            interface=args.interface,
            whitelist_file=args.whitelist,
            scan_interval=args.scan_interval,
            use_gps=args.gps,
            alert_threshold=args.threshold
        )
        
        print("\n" + "="*80)
        print(f"HIDDEN ROGUE AP DETECTOR")
        print(f"Interface: {args.interface} | Mode: {args.mode} | Alert threshold: {args.threshold} dBm")
        print(f"GPS enabled: {detector.use_gps} | Scan interval: {args.scan_interval} seconds")
        print(f"Whitelist: {args.whitelist} | Output: {args.output}")
        print("="*80 + "\n")
        
        print("Starting detector. Press Ctrl+C to stop.")
        detector.run(mode=args.mode)
    except Exception as e:
        logger.error(f"Error running detector: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
