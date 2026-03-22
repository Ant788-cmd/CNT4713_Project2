#pyright: basic
import secrets
import struct 
import sys
import socket

def generate_header(dname, txid):
    """
    
    """
    header = struct.pack("!HHHHHH", txid, 0x0000, 1, 0, 0, 0)
    qname = b''
    qdata = struct.pack("!HH", 1, 1)

    parts = dname.split('.')
    for part in parts:
        lenght = len(part)
        qname += struct.pack('!B', lenght)
        qname += part.encode('ascii')
    qname += b'\x00'

    return header + qname + qdata


def send_query(domain, server_ip):
    """
    """
    txid = secrets.randbits(16) 
    try:
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    except socket.error as e:
        print(f"Error creating socket: {e}")

    try:
        udp_socket.sendto(generate_header(domain, txid), (server_ip,53))
        data, addr = udp_socket.recvfrom(4096)
    except socket.timeout:
        print("Request timed out")
        return None,None
    except socket.error as e:
        print(f"Error during comunication: {e}")
        return None,None
    finally:
        udp_socket.close()

    return txid, data

def parse_domain_name(data, offset):
    """
    Helper to parse variable-length domain names, handling 0xC0 compression pointers.
    """
    labels = []
    original_offset = offset
    jumped = False

    while True:
        length = struct.unpack("!B", data[offset:offset+1])[0]
        
        if length == 0:
            offset += 1
            break
        
        if (length & 0xC0) == 0xC0:
            if not jumped:
                original_offset = offset + 2
            
            pointer_bytes = struct.unpack("!H", data[offset:offset+2])[0]
            offset = pointer_bytes & 0x3FFF
            jumped = True
        else:
            offset += 1
            # Read the string based on the length byte
            label = data[offset:offset+length].decode('ascii', errors='replace')
            labels.append(label)
            offset += length

    if not jumped:
        original_offset = offset

    return ".".join(labels), original_offset

def parse_records(data, offset, count):
    """
    Standalone helper to parse a specific number of Resource Records.
    Returns the list of parsed records AND the updated byte offset.
    """
    records = []
    for _ in range(count):
        name, offset = parse_domain_name(data, offset)
        
        # Unpack Type (2), Class (2), TTL (4), Data Length (2)
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
        offset += 10
        
        rdata_raw = data[offset:offset+rdlength]
        rdata_decoded = None
        
        if rtype == 1: # A Record (IPv4)
            rdata_decoded = socket.inet_ntoa(rdata_raw)
        elif rtype == 2 or rtype == 5: # NS or CNAME Record
            rdata_decoded, _ = parse_domain_name(data, offset)
        
        records.append({
            "name": name,
            "type": rtype,
            "class": rclass,
            "ttl": ttl,
            "rdlength": rdlength,
            "rdata_decoded": rdata_decoded
        })
        offset += rdlength
        
    return records, offset

def parse_response(txid, data):
    """
    Unpacks the DNS response using the struct module.
    """
    # 1. Unpack Header
    header = struct.unpack("!HHHHHH", data[:12])
    txid_recv, flags, qdcount, ancount, nscount, arcount = header
    
    if txid_recv != txid:
        print("Warning: Transaction ID mismatch!")

    offset = 12

    # 2. Skip over the Questions section
    for _ in range(qdcount):
        _, offset = parse_domain_name(data, offset)
        offset += 4  # Skip QTYPE and QCLASS

    # 3. Parse each section sequentially, capturing the updated offset each time
    answers, offset = parse_records(data, offset, ancount)
    authorities, offset = parse_records(data, offset, nscount)
    additionals, offset = parse_records(data, offset, arcount)

    # 4. Return the dictionary structure
    return {
        "header_counts": {"ancount": ancount, "nscount": nscount, "arcount": arcount},
        "answers": answers,
        "authorities": authorities,
        "additionals": additionals
    }

def display_response(parsed):
    counts = parsed["header_counts"]
    
    print("Reply received. Content overview:")
    print(f"{counts['ancount']} Answers.")
    print(f"{counts['nscount']} Intermediate Name Servers.")
    print(f"{counts['arcount']} Additional Information Records.")

    print("Answers section:")
    for rr in parsed["answers"]:
        if rr["type"] == 1: # A Record
            print(f"    Name : {rr['name']} IP : {rr['rdata_decoded']}")
        elif rr["type"] == 5: # CNAME Record
            print(f"    Name : {rr['name']} Alias : {rr['rdata_decoded']}")

    print("Authority Section:")
    for rr in parsed["authorities"]:
        if rr["type"] == 2: # NS Record
            print(f"    Name : {rr['name']} Name Server: {rr['rdata_decoded']}")

    print("Additional Information Section:")
    for rr in parsed["additionals"]:
        if rr["type"] == 1: # A Record
            print(f"    Name : {rr['name']} IP : {rr['rdata_decoded']}")

def extract_final_ips(parsed):
    final_ips = []
    for rr in parsed["answers"]:
        if rr["type"] == 1:
            final_ips.append(rr["rdata_decoded"])
    return final_ips


def extract_next_server_ip(parsed):
    for rr in parsed["additionals"]:
        if rr["type"] == 1:
            return rr["rdata_decoded"]
    return None


def resolve(domain, root_ip):
    current_server = root_ip
    max_steps = 10

    for step in range(1, max_steps + 1):
        print("----------------------------------------------------------------")
        print(f"DNS server to query: {current_server}")

        txid, raw_response = send_query(domain, current_server)

        if raw_response is None:
            print("No response received.")
            return

        parsed = parse_response(txid, raw_response)
        display_response(parsed)

        final_ips = extract_final_ips(parsed)
        if final_ips:
            for ip in final_ips:
                print(ip)
            return

        next_server_ip = extract_next_server_ip(parsed)
        if next_server_ip is None:
            print("Could not find intermediate DNS server IP.")
            return
        current_server = next_server_ip

    print("Reached maximum number of steps without resolution.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 mydns.py <domain-name> <root-dns-ip>")
        sys.exit(1)

    domain = sys.argv[1]
    root_ip = sys.argv[2]

    resolve(domain, root_ip)
