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

        for stack, (plugin, log_path) in self.stack_log_info.items():
            print(f"\n--- Stack: {stack} ---")
            if log_path:
                if log_path.is_dir():
                    print(f"Directory: {log_path}")
                    self.collect_directory_logs(log_path, plugin)
                else:
                    if plugin == "pcap1":
                        print(f"PCAP File: {log_path}")
                        self.collect_pcap_file(log_path)
                    else:
                        print(f"Log file: {log_path}")
                        self.collect_log_file(log_path)
            else:
                print("No log file or directory specified for this plugin.")

    def collect_log_file(self, log_file):
        if not log_file.exists():
            print(f"Error: Log file '{log_file}' does not exist.")
            return

        try:
            with open(log_file, "r") as f:
                for line in f:
                    print(line.strip())
        except Exception as e:
            print(f"Error reading file '{log_file}': {e}")

    def collect_directory_logs(self, log_dir, plugin):
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
                self.collect_log_file(log_file)
        except Exception as e:
            print(f"Error reading directory '{log_dir}': {e}")

    def collect_pcap_file(self, pcap_file):
        if not pcap_file.exists():
            print(f"Error: PCAP file '{pcap_file}' does not exist.")
            return

        try:
            result = subprocess.run(["tcpdump", "-nn", "-r", str(pcap_file)], capture_output=True, text=True)
            print(result.stdout)
        except Exception as e:
            print(f"Error reading PCAP file '{pcap_file}': {e}")


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
        print("1. Display all logs")
        print("2. Exit")

        choice = input("Enter your choice: ").strip()
        if choice == "1":
            log_collector.display_logs()
        elif choice == "2":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
