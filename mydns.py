import sys


def send_query(domain, server_ip):
    raise NotImplementedError


def parse_response(txid, data):
    raise NotImplementedError


def display_response(parsed):
    raise NotImplementedError


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

    print(f"[START] Domain: {domain}")
    print(f"[SEND QUERY TO ROOT DNS SERVER] {root_ip}")

    for step in range(1, max_steps + 1):
        txid, raw_response = send_query(domain, current_server)

        if raw_response is None:
            print("[STOP] No response received.")
            return

        if step == 1:
            print(f"[RECEIVE REPLY FROM ROOT DNS SERVER] {current_server}")
        else:
            print(f"[RECEIVE REPLY FROM INTERMEDIATE DNS SERVER] {current_server}")

        parsed = parse_response(txid, raw_response)

        print("[DISPLAY SERVER REPLY CONTENT]")
        display_response(parsed)

        final_ips = extract_final_ips(parsed)
        if final_ips:
            print("[DISPLAY IPS FOR QUERIED DOMAIN NAME]")
            for ip in final_ips:
                print(ip)
            return

        next_server_ip = extract_next_server_ip(parsed)
        if next_server_ip is None:
            print("[STOP] Could not find intermediate DNS server IP.")
            return

        print(f"[EXTRACT INTERMEDIATE DNS SERVER IP] {next_server_ip}")
        print(f"[SEND QUERY TO INTERMEDIATE SERVER] {next_server_ip}")

        current_server = next_server_ip

    print("[STOP] Reached maximum number of steps without resolution.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 mydns.py <domain-name> <root-dns-ip>")
        sys.exit(1)

    domain = sys.argv[1]
    root_ip = sys.argv[2]

    resolve(domain, root_ip)
