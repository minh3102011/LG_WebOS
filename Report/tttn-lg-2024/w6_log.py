import json
import re
from scapy.all import *


def get_protocol_name(proto_number):
    proto_dict = {
        1: "ICMP",
        6: "TCP",
        17: "UDP",
        58: "ICMPv6",
        89: "OSPF",
        132: "SCTP",
    }
    return proto_dict.get(proto_number, f"Unknown Protocol ({proto_number})")


def parse_ulogd_config(file_path, filter_types):
    stack_info = []
    stack_names = []
    stack_types = {}
    section_params = {}
    current_section = None

    with open(file_path, 'r') as f:
        lines = f.readlines()

    for line in lines:
        line = line.strip()
        if not line or line.startswith(';') or line.startswith('#'):
            continue

        if line.startswith('[') and line.endswith(']'):
            current_section = line[1:-1]
            section_params[current_section] = []

        elif current_section == 'global' and line.startswith('stack='):
            stacks = line[len('stack='):].split(',')
            for stack in stacks:
                stack_name, stack_type = stack.split(':')
                if any(type_ in stack_type for type_ in filter_types):
                    stack_names.append(stack_name)
                    stack_types[stack_name] = stack_type

        elif current_section in stack_names:
            if '=' in line:
                key, value = line.split('=', 1)
                value = value.replace('"', '')
                section_params[current_section].append(
                    (key.strip(), value.strip()))

    for stack_name in stack_names:
        if stack_name in section_params:
            temp_stack = {
                'name': stack_name,
                'type': stack_types[stack_name],
                'variables': {key: value for key, value in section_params[stack_name]}
            }
            if temp_stack not in stack_info:
                stack_info.append(temp_stack)

    return stack_info


def read_file_LOGEMU(stack):
    file_path = stack["variables"]["file"]

    regex = r'MAC=([0-9A-Fa-f:]+) SRC=([\d.]+) DST=([\d.]+) .*? PROTO=([A-Za-z]+)'

    try:
        with open(file_path, 'r') as file:
            content = file.read()

        matches = re.findall(regex, content)
        result = []
        for match in matches:
            combined_mac, src_ip, dst_ip, proto = match
            dst_mac = combined_mac[:17]
            src_mac = combined_mac[18:35]

            result.append({
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "proto": proto
            })

        return result

    except FileNotFoundError:
        return f"The file at {file_path} was not found."
    except IOError as e:
        return f"Error reading the file: {e}"


def read_file_PCAP(stack):

    file_path = stack["variables"]["file"]

    packets = rdpcap(file_path)

    result = []

    for packet in packets:
        src_mac = ''
        dst_mac = ''
        src_ip = ''
        dst_ip = ''
        proto = ''

        if packet.haslayer(Ether):
            src_mac = packet[Ether].src
            dst_mac = packet[Ether].dst
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = get_protocol_name(packet[IP].proto)
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            proto = get_protocol_name(packet[IPv6].nh)
        elif packet.haslayer(ARP):
            src_ip = packet[ARP].psrc
            dst_ip = packet[ARP].pdst
            proto = "ARP"

        result.append({
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "proto": proto
        })
    return result


def read_file_GPRINT(stack):
    patterns = {
        'ip.saddr': r'ip.saddr=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
        'ip.daddr': r'ip.daddr=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)',
        'mac.saddr.str': r'mac.saddr.str=([0-9a-fA-F:]+)',
        'mac.daddr.str': r'mac.daddr.str=([0-9a-fA-F:]+)',
        'ip.protocol': r'ip.protocol=([0-9]+)'
    }

    result = []

    file_path = stack["variables"]["file"]

    with open(file_path, 'r') as file:
        for line in file:
            fields = {
                'ip.saddr': None,
                'ip.daddr': None,
                'mac.saddr.str': None,
                'mac.daddr.str': None,
                'ip.protocol': None
            }

            for field, pattern in patterns.items():
                match = re.search(pattern, line)
                if match:
                    fields[field] = match.group(1)

            result.append({
                "src_mac": fields['mac.saddr.str'],
                "dst_mac": fields['mac.daddr.str'],
                "src_ip": fields['ip.saddr'],
                "dst_ip": fields['ip.daddr'],
                "proto": get_protocol_name(int(fields['ip.protocol']))
            })
    
    return result

def read_file_JSON(stack):

    result = []

    file_path = stack["variables"]["file"]

    with open(file_path, 'r') as f:
        for line in f:
            # Parse the JSON data from the line
            data = json.loads(line)
            
            # Extract the required fields
            src_mac = data.get("mac.saddr.str")
            dst_mac = data.get("mac.daddr.str")
            src_ip = data.get("src_ip")
            dst_ip = data.get("dest_ip")
            proto = data.get("ip.protocol")
            
            result.append({
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "proto": get_protocol_name(int(proto))
            })
    return result


file_path = '/etc/ulogd.conf'

filter_types = ['LOGEMU', 'PCAP', 'GPRINT', 'JSON']

stacks = parse_ulogd_config(file_path, filter_types)

result = []

for stack in stacks:
    match stack['type']:
        case 'LOGEMU':
            result.extend(read_file_LOGEMU(stack))
        case 'PCAP':
            result.extend(read_file_PCAP(stack))
        case 'GPRINT':
            result.extend(read_file_GPRINT(stack))
        case 'JSON':
            result.extend(read_file_JSON(stack))
        case _:
            pass
