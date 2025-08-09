import re
import json
from pathlib import Path
import subprocess

class UlogdConfigParser:
    def __init__(self, config_path="/etc/ulogd.conf"):
        self.config_path = Path(config_path)
        self.stacks = {}
        self.plugin_files = {}
        self.valid_plugins = {"pcap1", "gp1", "op1", "emu1", "json1", "xml1"}

    def parse_config(self):
        if not self.config_path.exists():
            print(f"Error: Configuration file '{self.config_path}' does not exist.")
            return False

        print(f"Parsing configuration file: {self.config_path}")
        current_plugin = None

        try:
            with open(self.config_path, "r") as f:
                for line in f:
                    line = line.strip()

                    if line.startswith("stack=") and not line.startswith("#"):
                        stack_name = re.search(r"stack=([^:]+):", line).group(1)
                        plugin_matches = re.findall(r",([^:]+):(\w+)", line)
                        for plugin_name, plugin_type in plugin_matches:
                            if plugin_name in self.valid_plugins:
                                self.stacks[stack_name] = plugin_name

                    elif re.match(r"^\[.*\]$", line):
                        current_plugin = line.strip("[]")

                    elif "file=" in line and not line.startswith("#"):
                        match = re.search(r'file="([^"]+)"', line)
                        if match and current_plugin:
                            log_file = match.group(1)
                            self.plugin_files[current_plugin] = Path(log_file)

                    elif "directory=" in line and not line.startswith("#"):
                        match = re.search(r'directory="([^"]+)"', line)
                        if match and current_plugin:
                            log_dir = match.group(1)
                            self.plugin_files[current_plugin] = Path(log_dir)

        except Exception as e:
            print(f"Error parsing configuration file: {e}")
            return False

        return True

    def get_stack_log_info(self):
        stack_log_info = {}
        for stack, plugin in self.stacks.items():
            log_path = self.plugin_files.get(plugin)
            stack_log_info[stack] = (plugin, log_path)
        return stack_log_info

class LogCollector:
    def __init__(self, stack_log_info):
        self.stack_log_info = stack_log_info

    def display_logs(self):
        if not self.stack_log_info:
            print("No active stacks or log files found.")
            return

        all_logs = []

        for stack, (plugin, log_path) in self.stack_log_info.items():
            print(f"\n--- Stack: {stack} ---")
            if log_path:
                if log_path.is_dir():
                    print(f"Directory: {log_path}")
                    self.collect_directory_logs(log_path, plugin, all_logs)
                else:
                    if plugin == "pcap1":
                        print(f"PCAP File: {log_path}")
                        self.collect_pcap_file(log_path, all_logs)
                    else:
                        print(f"Log file: {log_path}")
                        self.collect_log_file(log_path, plugin, all_logs)
            else:
                print("No log file or directory specified for this plugin.")

        self.display_log_table(all_logs)

    def collect_log_file(self, log_file, plugin, all_logs):
        if not log_file.exists():
            print(f"Error: Log file '{log_file}' does not exist.")
            return

        try:
            with open(log_file, "r") as f:
                for line in f:
                    if plugin == "emu1":
                        log = self.process_syslogemu_log(line)
                    elif plugin == "json1":
                        log = self.process_json_log(line)
                    elif plugin == "gp1":
                        log = self.process_gprint_log(line)
                    elif plugin == "op1":
                        log = self.process_oprint_log(line)
                    else:
                        continue
                    
                    if log:
                        all_logs.append(log)
        except Exception as e:
            print(f"Error reading file '{log_file}': {e}")

    def collect_directory_logs(self, log_dir, plugin, all_logs):
        file_extension = {
            "xml1": ".xml",
            "json1": ".json",
            "emu1": ".log",
            "gp1": ".log",
            "op1": ".log",
        }.get(plugin, None)

        try:
            log_files = list(log_dir.glob(f"*{file_extension}")) if file_extension else []
            if not log_files:
                print(f"No log files with extension '{file_extension}' found in directory '{log_dir}'.")
                return

            for log_file in log_files:
                self.collect_log_file(log_file, plugin, all_logs)
        except Exception as e:
            print(f"Error reading directory '{log_dir}': {e}")

    def collect_pcap_file(self, pcap_file, all_logs):
        if not pcap_file.exists():
            print(f"Error: PCAP file '{pcap_file}' does not exist.")
            return

        try:
            result = subprocess.run(["tcpdump", "-nn", "-r", str(pcap_file)], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                log = self.process_pcap_log(line)
                if log:
                    all_logs.append(log)
        except Exception as e:
            print(f"Error reading PCAP file '{pcap_file}': {e}")

    def process_syslogemu_log(self, line):
        match = re.match(r"(\S+ \S+ \S+) .+ SRC=(\S+) DST=(\S+) .+ PROTO=(\S+) MAC=(\S+)", line)
        if match:
            time, ip_src, ip_dst, protocol, mac_address = match.groups()
            return {"Time": time, "IP SRC": ip_src, "IP DST": ip_dst, "Protocol": protocol, "MAC Address": mac_address}
        return None

    def process_json_log(self, line):
        try:
            log = json.loads(line)
            return {
                "Time": log.get("timestamp", "Unknown"),
                "IP SRC": log.get("src_ip", "Unknown"),
                "IP DST": log.get("dest_ip", "Unknown"),
                "Protocol": log.get("ip.protocol", "Unknown"),
                "MAC Address": log.get("mac.str", "N/A")
            }
        except json.JSONDecodeError:
            print(f"Error processing JSON log: {line}")
            return None

    def process_pcap_log(self, line):
        match = re.match(r"(\S+) IP (\S+) > (\S+): (\S+)", line)
        if match:
            time, ip_src, ip_dst, protocol = match.groups()
            return {
                "Time": time, "IP SRC": ip_src, "IP DST": ip_dst, "Protocol": protocol, "MAC Address": "N/A"
            }
        return None

    def process_gprint_log(self, line):
        match = re.match(r"timestamp=(\S+),.*ip.saddr=(\S+),ip.daddr=(\S+),ip.protocol=(\S+)", line)
        if match:
            timestamp, ip_src, ip_dst, protocol = match.groups()
            return {
                "Time": timestamp, "IP SRC": ip_src, "IP DST": ip_dst, "Protocol": protocol, "MAC Address": "N/A"
            }
        return None

    def process_oprint_log(self, line):
        match = re.match(r".*ip.saddr=(\S+),ip.daddr=(\S+),ip.protocol=(\S+),.*MAC=(\S+)", line)
        if match:
            ip_src, ip_dst, protocol, mac_address = match.groups()
            return {
                "Time": "Unknown",
                "IP SRC": ip_src,
                "IP DST": ip_dst,
                "Protocol": protocol,
                "MAC Address": mac_address
            }
        return None

    def display_log_table(self, logs):
        if logs:
            print(f"\n{'Time':<30}{'IP SRC':<20}{'IP DST':<20}{'Protocol':<20}{'MAC Address':<20}")
            print("-" * 110)
            for log in logs:
                print(f"{log['Time']:<30}{log['IP SRC']:<20}{log['IP DST']:<20}{log['Protocol']:<20}{log['MAC Address']:<20}")
        else:
            print("No logs to display.")

def main():
    config_parser = UlogdConfigParser()
    if not config_parser.parse_config():
        return

    stack_log_info = config_parser.get_stack_log_info()
    print("\nDetected stacks and log paths:")
    for stack, (plugin, log_path) in stack_log_info.items():
        log_path_display = log_path if log_path else "No log file or directory specified"
        print(f"  Stack: {stack}, Plugin: {plugin}, Path: {log_path_display}")

    log_collector = LogCollector(stack_log_info)

    while True:
        print("\nOptions:")
        print("1. Display all logs in a unified table")
        print("2. Exit")

        option = input("Choose an option: ")
        if option == "1":
            log_collector.display_logs()
        elif option == "2":
            break
        else:
            print("Invalid option. Please choose again.")

if __name__ == "__main__":
    main()
