"""
Device Scanning and Continuous Monitoring Module
"""

import os
import psutil
import platform
import socket
import json
import hashlib
from datetime import datetime, timedelta
from threading import Thread, Event
import time
import subprocess
import sys
from pathlib import Path

class DeviceScanner:
    """Device scanning and monitoring class"""
    
    def __init__(self, user_id):
        self.user_id = user_id
        self.scan_results = {}
        self.monitoring_active = False
        self.monitoring_thread = None
        self.stop_event = Event()
        
    def collect_device_info(self):
        """Collect comprehensive device information"""
        device_info = {
            'scan_timestamp': datetime.now().isoformat(),
            'system': self._get_system_info(),
            'hardware': self._get_hardware_info(),
            'network': self._get_network_info(),
            'security': self._get_security_info(),
            'processes': self._get_process_list(),
            'startup_programs': self._get_startup_programs(),
            'installed_software': self._get_installed_software(),
            'filesystem': self._scan_filesystem(),
            'registry': self._check_registry() if platform.system() == 'Windows' else {}
        }
        
        # Calculate initial security score
        device_info['security_score'] = self._calculate_security_score(device_info)
        
        return device_info
    
    def _get_system_info(self):
        """Get operating system information"""
        return {
            'os': platform.system(),
            'os_version': platform.version(),
            'os_release': platform.release(),
            'architecture': platform.architecture()[0],
            'hostname': socket.gethostname(),
            'python_version': platform.python_version(),
            'current_user': os.getlogin() if hasattr(os, 'getlogin') else 'unknown'
        }
    
    def _get_hardware_info(self):
        """Get hardware information"""
        try:
            cpu_info = {
                'cores': psutil.cpu_count(logical=False),
                'logical_cores': psutil.cpu_count(logical=True),
                'frequency': psutil.cpu_freq().current if psutil.cpu_freq() else None
            }
        except:
            cpu_info = {}
        
        try:
            memory_info = {
                'total': psutil.virtual_memory().total,
                'available': psutil.virtual_memory().available,
                'percent_used': psutil.virtual_memory().percent
            }
        except:
            memory_info = {}
        
        try:
            disk_info = []
            for part in psutil.disk_partitions():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    disk_info.append({
                        'device': part.device,
                        'mountpoint': part.mountpoint,
                        'fstype': part.fstype,
                        'total': usage.total,
                        'used': usage.used,
                        'free': usage.free,
                        'percent': usage.percent
                    })
                except:
                    continue
        except:
            disk_info = []
        
        return {
            'cpu': cpu_info,
            'memory': memory_info,
            'disks': disk_info
        }
    
    def _get_network_info(self):
        """Get network information"""
        try:
            interfaces = []
            for name, addrs in psutil.net_if_addrs().items():
                interface_info = {
                    'name': name,
                    'addresses': []
                }
                for addr in addrs:
                    interface_info['addresses'].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask if addr.netmask else None,
                        'broadcast': addr.broadcast if addr.broadcast else None
                    })
                interfaces.append(interface_info)
        except:
            interfaces = []
        
        try:
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                connections.append({
                    'fd': conn.fd,
                    'family': str(conn.family),
                    'type': str(conn.type),
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                })
        except:
            connections = []
        
        return {
            'interfaces': interfaces,
            'connections': connections[:50]  # Limit to first 50 connections
        }
    
    def _get_security_info(self):
        """Get security-related information"""
        # Check for common security software
        security_software = self._check_security_software()
        
        # Check firewall status
        firewall_status = self._check_firewall()
        
        # Check for updates
        updates_status = self._check_updates()
        
        return {
            'security_software': security_software,
            'firewall': firewall_status,
            'updates': updates_status,
            'antivirus_installed': len(security_software.get('antivirus', [])) > 0,
            'firewall_enabled': firewall_status.get('enabled', False)
        }
    
    def _get_process_list(self):
        """Get running processes"""
        processes = []
        try:
            for proc in psutil.process_iter(['pid', 'name', 'username', 'memory_percent', 'cpu_percent']):
                try:
                    processes.append({
                        'pid': proc.info['pid'],
                        'name': proc.info['name'],
                        'user': proc.info['username'],
                        'memory': proc.info['memory_percent'],
                        'cpu': proc.info['cpu_percent']
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except:
            pass
        
        return processes[:100]  # Limit to 100 processes
    
    def _get_startup_programs(self):
        """Get startup programs"""
        startup_programs = []
        try:
            if platform.system() == "Windows":
                # Windows startup programs
                startup_paths = [
                    os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
                    os.path.join(os.getenv('PROGRAMDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
                ]
                
                for path in startup_paths:
                    if os.path.exists(path):
                        for item in os.listdir(path):
                            item_path = os.path.join(path, item)
                            if os.path.isfile(item_path):
                                startup_programs.append({
                                    'name': item,
                                    'path': item_path,
                                    'type': 'startup'
                                })
            
            elif platform.system() == "Darwin":  # macOS
                # macOS startup items
                plist_paths = [
                    os.path.expanduser('~/Library/LaunchAgents'),
                    '/Library/LaunchAgents',
                    '/Library/LaunchDaemons',
                    '/System/Library/LaunchAgents',
                    '/System/Library/LaunchDaemons'
                ]
                
                for plist_path in plist_paths:
                    if os.path.exists(plist_path):
                        for item in os.listdir(plist_path):
                            if item.endswith('.plist'):
                                startup_programs.append({
                                    'name': item,
                                    'path': os.path.join(plist_path, item),
                                    'type': 'launchd'
                                })
            
            else:  # Linux
                # Linux startup services
                init_d = '/etc/init.d'
                if os.path.exists(init_d):
                    for item in os.listdir(init_d):
                        if os.path.isfile(os.path.join(init_d, item)):
                            startup_programs.append({
                                'name': item,
                                'path': os.path.join(init_d, item),
                                'type': 'init.d'
                            })
        except:
            pass
        
        return startup_programs
    
    def _get_installed_software(self):
        """Get installed software (limited information due to permissions)"""
        software_list = []
        
        try:
            if platform.system() == "Windows":
                import winreg
                # Read from Windows registry
                reg_paths = [
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
                ]
                
                for reg_path in reg_paths:
                    try:
                        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path)
                        for i in range(0, winreg.QueryInfoKey(key)[0]):
                            try:
                                subkey_name = winreg.EnumKey(key, i)
                                subkey = winreg.OpenKey(key, subkey_name)
                                display_name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                if display_name:
                                    software_list.append(display_name)
                                winreg.CloseKey(subkey)
                            except WindowsError:
                                continue
                        winreg.CloseKey(key)
                    except WindowsError:
                        continue
        except:
            pass
        
        return list(set(software_list))[:50]  # Remove duplicates and limit
    
    def _scan_filesystem(self, max_depth=2):
        """Scan filesystem for suspicious files"""
        suspicious_files = []
        
        # Common suspicious directories
        scan_paths = [
            os.path.expanduser("~"),
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Desktop")
        ]
        
        # Add system temp directories
        temp_paths = [
            os.environ.get('TEMP', ''),
            os.environ.get('TMP', ''),
            '/tmp',
            '/var/tmp'
        ]
        
        scan_paths.extend([p for p in temp_paths if p and os.path.exists(p)])
        
        # Suspicious file extensions
        suspicious_extensions = {'.exe', '.bat', '.cmd', '.vbs', '.ps1', '.sh', '.jar', '.js', '.py'}
        
        for scan_path in scan_paths:
            if os.path.exists(scan_path):
                try:
                    for root, dirs, files in os.walk(scan_path):
                        current_depth = root[len(scan_path):].count(os.sep)
                        if current_depth > max_depth:
                            continue
                        
                        for file in files:
                            file_path = os.path.join(root, file)
                            file_ext = os.path.splitext(file)[1].lower()
                            
                            if file_ext in suspicious_extensions:
                                try:
                                    file_stat = os.stat(file_path)
                                    suspicious_files.append({
                                        'path': file_path,
                                        'size': file_stat.st_size,
                                        'modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                                        'extension': file_ext,
                                        'reason': 'suspicious_extension'
                                    })
                                except:
                                    continue
                except:
                    continue
        
        return suspicious_files[:20]  # Limit to 20 files
    
    def _check_registry(self):
        """Check Windows registry for suspicious entries"""
        registry_findings = []
        
        try:
            import winreg
            
            # Common malware registry locations
            suspicious_locations = [
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
                r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
            ]
            
            for location in suspicious_locations:
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, location)
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                            # Check for suspicious values
                            if any(susp in value.lower() for susp in ['temp', 'appdata', 'userprofile']):
                                registry_findings.append({
                                    'location': location,
                                    'name': name,
                                    'value': value,
                                    'reason': 'suspicious_path'
                                })
                            i += 1
                        except WindowsError:
                            break
                    winreg.CloseKey(key)
                except WindowsError:
                    continue
        except:
            pass
        
        return registry_findings
    
    def _check_security_software(self):
        """Check for installed security software"""
        security_software = {
            'antivirus': [],
            'firewall': [],
            'other': []
        }
        
        # Common antivirus process names
        antivirus_processes = {
            'Windows Defender': ['MsMpEng.exe', 'NisSrv.exe'],
            'Avast': ['AvastSvc.exe', 'AvastUI.exe'],
            'AVG': ['AVGSvc.exe', 'AVGUI.exe'],
            'McAfee': ['Mcshield.exe', 'Mfeann.exe'],
            'Norton': ['ccSvcHst.exe', 'Norton.exe'],
            'Kaspersky': ['avp.exe', 'avpui.exe'],
            'Bitdefender': ['bdagent.exe', 'vsserv.exe'],
            'Malwarebytes': ['mbam.exe', 'MBAMService.exe']
        }
        
        try:
            running_processes = [p.name().lower() for p in psutil.process_iter(['name'])]
            
            for av_name, processes in antivirus_processes.items():
                for process in processes:
                    if process.lower() in running_processes:
                        security_software['antivirus'].append(av_name)
                        break
        except:
            pass
        
        return security_software
    
    def _check_firewall(self):
        """Check firewall status"""
        firewall_status = {
            'enabled': False,
            'details': {}
        }
        
        try:
            if platform.system() == "Windows":
                # Check Windows Firewall
                import subprocess
                result = subprocess.run(
                    ['netsh', 'advfirewall', 'show', 'allprofiles'],
                    capture_output=True, text=True
                )
                
                if 'ON' in result.stdout:
                    firewall_status['enabled'] = True
                
                firewall_status['details'] = {
                    'output': result.stdout[:500]  # Limit output size
                }
            
            elif platform.system() == "Darwin":  # macOS
                result = subprocess.run(
                    ['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getglobalstate'],
                    capture_output=True, text=True
                )
                
                if 'enabled' in result.stdout.lower():
                    firewall_status['enabled'] = True
                
                firewall_status['details'] = {
                    'output': result.stdout
                }
            
            else:  # Linux
                # Check for common Linux firewalls
                firewalls = ['ufw', 'firewalld', 'iptables']
                for fw in firewalls:
                    result = subprocess.run(['which', fw], capture_output=True)
                    if result.returncode == 0:
                        firewall_status['enabled'] = True
                        firewall_status['details']['firewall'] = fw
                        break
        except:
            pass
        
        return firewall_status
    
    def _check_updates(self):
        """Check for system updates"""
        updates_status = {
            'available': False,
            'last_checked': None,
            'details': {}
        }
        
        try:
            if platform.system() == "Windows":
                import winreg
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                        r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Detect")
                    last_check, _ = winreg.QueryValueEx(key, "LastSuccessTime")
                    winreg.CloseKey(key)
                    updates_status['last_checked'] = datetime.fromtimestamp(last_check).isoformat()
                except:
                    updates_status['last_checked'] = 'unknown'
            
            elif platform.system() == "Darwin":  # macOS
                result = subprocess.run(
                    ['softwareupdate', '-l'],
                    capture_output=True, text=True
                )
                
                if 'No new software available' not in result.stdout:
                    updates_status['available'] = True
                
                updates_status['details']['output'] = result.stdout[:500]
            
            else:  # Linux
                # Check package manager
                managers = ['apt', 'yum', 'dnf', 'pacman', 'zypper']
                for mgr in managers:
                    result = subprocess.run(['which', mgr], capture_output=True)
                    if result.returncode == 0:
                        updates_status['details']['package_manager'] = mgr
                        
                        if mgr == 'apt':
                            result = subprocess.run(['apt', 'list', '--upgradable'], capture_output=True, text=True)
                            if 'upgradable' in result.stdout:
                                updates_status['available'] = True
                        break
        except:
            pass
        
        return updates_status
    
    def _calculate_security_score(self, device_info):
        """Calculate security score based on device information"""
        score = 100  # Start with perfect score
        
        # Deduct for missing security software
        security_info = device_info.get('security', {})
        if not security_info.get('antivirus_installed', False):
            score -= 20
        
        if not security_info.get('firewall_enabled', False):
            score -= 15
        
        # Deduct for suspicious files
        filesystem = device_info.get('filesystem', [])
        if filesystem:
            score -= min(len(filesystem) * 2, 30)
        
        # Deduct for many startup programs
        startup = device_info.get('startup_programs', [])
        if len(startup) > 10:
            score -= 10
        
        # Deduct for high-risk processes
        processes = device_info.get('processes', [])
        risky_processes = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe']
        for proc in processes:
            if proc.get('name', '').lower() in risky_processes:
                score -= 5
        
        # Ensure score is between 0 and 100
        return max(0, min(100, score))
    
    def start_continuous_monitoring(self):
        """Start continuous device monitoring"""
        if self.monitoring_active:
            return False, "Monitoring already active"
        
        self.monitoring_active = True
        self.stop_event.clear()
        self.monitoring_thread = Thread(target=self._monitoring_loop, daemon=True)
        self.monitoring_thread.start()
        
        return True, "Continuous monitoring started"
    
    def stop_continuous_monitoring(self):
        """Stop continuous device monitoring"""
        if not self.monitoring_active:
            return False, "Monitoring not active"
        
        self.monitoring_active = False
        self.stop_event.set()
        if self.monitoring_thread:
            self.monitoring_thread.join(timeout=5)
        
        return True, "Continuous monitoring stopped"
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        scan_interval = 60  # Scan every 60 seconds
        last_scan = datetime.now()
        
        while not self.stop_event.is_set():
            try:
                # Perform periodic scan
                if (datetime.now() - last_scan).seconds >= scan_interval:
                    threats = self.perform_threat_scan()
                    if threats:
                        # Store threats or send notifications
                        self._handle_new_threats(threats)
                    last_scan = datetime.now()
                
                # Monitor real-time changes
                self._monitor_realtime_changes()
                
                # Sleep briefly
                time.sleep(5)
                
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(10)
    
    def perform_threat_scan(self):
        """Perform comprehensive threat scan"""
        threats = []
        
        try:
            # Check for new suspicious processes
            current_processes = self._get_process_list()
            suspicious_processes = self._detect_suspicious_processes(current_processes)
            threats.extend(suspicious_processes)
            
            # Check network connections
            network_info = self._get_network_info()
            suspicious_connections = self._detect_suspicious_connections(network_info)
            threats.extend(suspicious_connections)
            
            # Check file changes
            file_threats = self._detect_file_changes()
            threats.extend(file_threats)
            
        except Exception as e:
            print(f"Threat scan error: {e}")
        
        return threats
    
    def _detect_suspicious_processes(self, processes):
        """Detect suspicious processes"""
        threats = []
        
        suspicious_patterns = [
            'cryptominer', 'miner', 'backdoor', 'rat', 'trojan',
            'keylogger', 'ransom', 'malware', 'virus', 'worm'
        ]
        
        for proc in processes:
            proc_name = proc.get('name', '').lower()
            for pattern in suspicious_patterns:
                if pattern in proc_name:
                    threats.append({
                        'type': 'Suspicious Process',
                        'severity': 'high',
                        'details': f"Process {proc_name} matches suspicious pattern: {pattern}",
                        'process_info': proc,
                        'timestamp': datetime.now().isoformat()
                    })
                    break
        
        return threats
    
    def _detect_suspicious_connections(self, network_info):
        """Detect suspicious network connections"""
        threats = []
        
        suspicious_ports = [22, 23, 3389, 5900, 5901]  # SSH, Telnet, RDP, VNC
        suspicious_ips = ['192.168.', '10.', '172.16.', '127.0.0.1']
        
        connections = network_info.get('connections', [])
        for conn in connections:
            raddr = conn.get('raddr')
            if raddr:
                try:
                    ip, port = raddr.split(':')
                    port = int(port)
                    
                    # Check for suspicious ports
                    if port in suspicious_ports:
                        threats.append({
                            'type': 'Suspicious Network Connection',
                            'severity': 'medium',
                            'details': f"Connection to suspicious port {port} from {ip}",
                            'connection_info': conn,
                            'timestamp': datetime.now().isoformat()
                        })
                    
                    # Check for suspicious IP ranges
                    for suspicious_ip in suspicious_ips:
                        if ip.startswith(suspicious_ip):
                            threats.append({
                                'type': 'Internal Network Scanning',
                                'severity': 'low',
                                'details': f"Connection to internal IP {ip}",
                                'connection_info': conn,
                                'timestamp': datetime.now().isoformat()
                            })
                            break
                except:
                    continue
        
        return threats
    
    def _detect_file_changes(self):
        """Detect suspicious file changes"""
        # This is a simplified version
        # In production, you'd compare with a baseline
        return []
    
    def _handle_new_threats(self, threats):
        """Handle newly detected threats"""
        for threat in threats:
            print(f"Threat detected: {threat['type']} - {threat['details']}")
            # In production, you would:
            # 1. Save to database
            # 2. Send notifications
            # 3. Trigger alerts
    
    def _monitor_realtime_changes(self):
        """Monitor real-time system changes"""
        try:
            # Monitor CPU usage spikes
            cpu_percent = psutil.cpu_percent(interval=1)
            if cpu_percent > 90:
                print(f"High CPU usage detected: {cpu_percent}%")
            
            # Monitor memory usage
            memory_percent = psutil.virtual_memory().percent
            if memory_percent > 90:
                print(f"High memory usage detected: {memory_percent}%")
            
            # Monitor disk activity
            disk_io = psutil.disk_io_counters()
            if disk_io and disk_io.read_bytes > 100 * 1024 * 1024:  # 100MB
                print("High disk activity detected")
                
        except:
            pass