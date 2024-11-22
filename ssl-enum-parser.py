import csv
import os
import re
import argparse
from collections import defaultdict
import requests
from bs4 import BeautifulSoup


def parse_ssl_enum_ciphers(file_path):
    results = defaultdict(list)
    current_host = None
    current_port = None
    print(f"[+] Parsing {file_path}")
    with open(file_path, 'r') as f:
        for line in f:
            # Match IP
            host_match = re.match(
                r"Nmap scan report for ((?:(?:25[0-5]|2[0-4]\d|1\d{2}|\d{1,2})\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|\d{1,2}))", 
                line
            )

            if host_match:
                current_host = host_match.group(1)
                current_port = None
                current_ver = None
                continue

            # Match port
            port_match = re.match(r"(\d{1,5})/tcp\s+open", line)
            if port_match:
                current_port = port_match.group(1)
                current_ver = None
                continue
            
            # Match tls version
            ver_match = re.match(r"\|\s+(TLSv1\.\d):", line)
            if ver_match:
                current_ver = ver_match.group(1)
                continue

            # Match cipher details
            if "TLS_" in line or current_port:
                cipher_match = re.match(r"\|\s+(TLS_.*) \(", line)
                if cipher_match:
                    results[(current_host, int(current_port), current_ver)].append(cipher_match.group(1))
    return results


def process_directory(directory_path, dir_keyword):
    all_results = {}
    for filename in os.listdir(directory_path):
        if dir_keyword in filename:
            file_path = os.path.join(directory_path, filename)
            results = parse_ssl_enum_ciphers(file_path)
            all_results[filename] = results
    return all_results

def process_file(file_path):
    return {os.path.basename(file_path): parse_ssl_enum_ciphers(file_path)}

def fetch_cipher_info(cipher_name, cipher_dict):
    url = f"https://ciphersuite.info/cs/{cipher_name}"
    
    if cipher_name in cipher_dict:
        print(f"[=] Already downloaded, skipping download from https://ciphersuite.info/cs/{cipher_name}")
        return cipher_dict
    
    response = requests.get(url)
    if response.status_code != 200:
        print(f"[-] Failed to fetch the page for '{cipher_name}'. Status code: {response.status_code}")
        cipher_dict[cipher_name] = {
            'status': "",
            'triangle': [],
            'octagon': []
        }
        return cipher_dict
    print(f"[+] Download from https://ciphersuite.info/cs/{cipher_name}")

    # Parse the HTML content
    html_content = response.text
    soup = BeautifulSoup(html_content, 'html.parser')

    # Extract exclamation-related bold texts
    triangle_alerts = soup.find_all("div", class_="alert alert-warning")
    octagon_alerts = soup.find_all("div", class_="alert alert-danger")
    
    triangle_texts = [alert.find("strong").text.replace(':', '').strip() for alert in triangle_alerts if alert.find("strong")]
    octagon_texts = [alert.find("strong").text.replace(':', '').strip() for alert in octagon_alerts if alert.find("strong")]
    
    cipher_status = None
    h1_element = soup.find("h1", class_="mb-4")
    if h1_element:
        status_span = h1_element.find("span", class_="badge")
        if status_span:
            cipher_status = status_span.text.strip()
        else:
            # If class not found, look for preceding span to the cipher name
            preceding_span = h1_element.find("span", class_="break-all")
            if preceding_span:
                preceding_sibling = preceding_span.find_previous_sibling("span")
                if preceding_sibling:
                    cipher_status = preceding_sibling.text.strip()
    
    # Add results to the dictionary
    cipher_dict[cipher_name] = {
        'status': cipher_status,
        'triangle': triangle_texts,
        'octagon': octagon_texts
    }
    
    return cipher_dict

def generate_csv(final_res: dict, csv_out: str):
    all_dict_keys = set()
    for val in final_res.values():
        all_dict_keys.update(val.keys())
    headers = ['IP', 'Port', 'Version', 'Cipher', 'Status'] + list(all_dict_keys)

    with open(csv_out, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        # Write headers
        writer.writerow(headers)
        
        # Write rows
        for (ip, port, version, cipher, status), details in final_res.items():
            row = [ip, port, version, cipher, status] + [details.get(key, '') for key in all_dict_keys]
            writer.writerow(row)

    print(f"[+] Output saved to {csv_out}")

def main():
    parser = argparse.ArgumentParser(description="Parse Nmap files for ssl-enum-ciphers output.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--dir", help="Directory containing Nmap files", type=str)
    group.add_argument("--file", help="Single Nmap file", type=str)
    parser.add_argument("--out", help="Path for csv output file", type=str, default="output.csv")
    parser.add_argument("--keyword", help="Keyword in filename when using --dir so that the script knows which files to parse", default="ssl-enum-cipher")

    args = parser.parse_args()

    temp_res = {}
    final_res = defaultdict(lambda: defaultdict(str))
    cipher_dict = {}
    triangles = set()
    octagons = set()

    if args.dir:
        if not os.path.isdir(args.dir):
            print(f"[-] Error: {args.dir} is not a valid directory.")
            return
        results = process_directory(args.dir, args.keyword)
    elif args.file:
        if not os.path.isfile(args.file):
            print(f"[-] Error: {args.file} is not a valid file.")
            return
        results = process_file(args.file)

    for _, data in results.items():
        for key, value in data.items():
            for v in value:
                cipher_dict = fetch_cipher_info(v, cipher_dict)
                temp_res[key + (v,)] = cipher_dict[v]

    for _, v1 in temp_res.items():
        triangles.update(v1['triangle'])
        octagons.update(v1['octagon'])

    for k1, v1 in temp_res.items():
        for t in triangles:
            final_res[k1 + (v1['status'],)][t] = True if t in temp_res[k1]['triangle'] else False
        for o in octagons:
            final_res[k1 + (v1['status'],)][t] = True if o in temp_res[k1]['octagon'] else False

    generate_csv(final_res, args.out)


if __name__ == "__main__":
    main()
