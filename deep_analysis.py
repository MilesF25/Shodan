import shodan
import nvdlib
from collections import Counter
from rich.console import Console
from rich.table import Table

import requests
import csv
import time
import os
import json


# update to do :Highest individual CVE score per device
def main():
    api_key = input("Enter your Shodan API key: ").strip()
    api = shodan.Shodan(api_key)  # use user key
    console = Console()

    query = input("Enter the rest of your Shodan query: ")

    # takes the query,api and console and returns a dict with shodan results
    og_query_results = city_report(query, api, console)  # dict

    # takes the shodan results and extracts the info into a list of dicts
    shodan_results = extract_shodan_match(og_query_results)  # list full of dicts

    # reads the cvs and scores them

    ranked_cves = calc(shodan_results)

    # takes the original results (list dict) and cves ranks (dict) and calculates the cve score in the og results
    final_score = add_scores_to_devices(shodan_results, ranked_cves)  # list, dict

    # easy display
    print_devices_table(final_score)

    ans = input("Would you like to write the result to a csv? yes/no?: ")
    if ans.lower() == "yes" or ans.lower() == "y":
        # csv save
        file_name = save_csvname()
        unique_name = uniquify(file_name)
        save_output(shodan_results, unique_name, query)
        # json format
        json_name = save_jsoname()
        json_unique = uniquify(json_name)
        json_dump_format(shodan_results, json_unique)

    else:
        print("Be sure to check how many tokens you have left")


# go through and add error handling

# this will just make sure there are no dupe files


def uniquify(path):
    filename, extension = os.path.splitext(path)
    counter = 1

    while os.path.exists(path):
        path = filename + " (" + str(counter) + ")" + extension
        counter += 1

    return path


def save_csvname(filename="devices_info.csv"):
    if os.path.exists(filename):
        new_file = uniquify(filename)
        return new_file
    else:
        return filename


# i am aware this could be done better but im a lazy
def save_jsoname(filename="device_info_dump.json"):
    if os.path.exists(filename):
        new_file = uniquify(filename)
        return new_file
    else:
        return filename


def json_dump_format(devices, filename):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(devices, f, indent=4, ensure_ascii=False)


# need to make it so thta it writes teh query to the top of the page,
def save_output(devices: list, filename: str, query: str):
    headers = ["ip", "port", "org", "product", "os", "cve"]

    with open(filename, "w", newline="", encoding="utf-8") as f:
        # Write query on the first line
        f.write(f"Query: {query}\n\n\n")  # query + 2 blank lines

        writer = csv.DictWriter(f, fieldnames=headers)
        writer.writeheader()

        for d in devices:
            if d["vulns"]:
                for cve in d["vulns"]:
                    writer.writerow(
                        {
                            "ip": d["ip"],
                            "port": d["port"],
                            "org": d["org"],
                            "product": d["product"],
                            "os": d["os"],
                            "cve": cve,
                        }
                    )
            else:
                writer.writerow(
                    {
                        "ip": d["ip"],
                        "port": d["port"],
                        "org": d["org"],
                        "product": d["product"],
                        "os": d["os"],
                        "cve": "None",
                    }
                )


# searchs iser query
def city_report(usr_query: str, api, console) -> dict:
    query = usr_query
    print(f"[*] Running query: {query}")

    try:
        results = api.search(query, limit=30)  # can get 50 but keep at 40 for api
    except shodan.APIError as e:
        print(f"[!] Shodan API Error: {e}")

    return results


# extracts the query into a list of dicts
def extract_shodan_match(results: dict) -> list:
    """
    Extracts useful fields from a Shodan host match safely.
    Always returns a dict with consistent keys.
    """
    if type(results) is dict:
        devices = []
        for match in results["matches"]:
            #         # Extract and structure each device's data

            device = {
                # Core identifiers
                "ip": match.get("ip_str", "N/A"),
                "port": match.get("port", "N/A"),
                "transport": match.get("transport", "N/A"),
                # Organization / network
                "org": match.get("org", "Unknown"),
                "asn": match.get("asn", "N/A"),
                "isp": match.get("isp", "N/A"),
                # Host identifiers
                # removed https
                # Software / service
                "product": match.get("product", "Unknown"),
                "version": match.get("version", "N/A"),
                "cpe": match.get("cpe", []),
                "os": match.get("os", "Unknown"),
                # Security
                "vulns": list(match.get("vulns", {}).keys()),  # just CVE IDs
                # removed ssl
                "ssh": match.get("ssh", {}),
                # Location
                "city": match.get("city", "Unknown"),
                "region_code": match.get("region_code", "Unknown"),
                "country_name": match.get("country_name", "Unknown"),
                "country_code": match.get("country_code", "XX"),
                "latitude": match.get("latitude", None),
                "longitude": match.get("longitude", None),
            }
            devices.append(device)

        return devices
    else:
        print("Expecting a dict")


# this calculates the cve scores by extracting the unique scores and using nist api to socre them
def calc(devices: list):
    all_vulns = []

    for devi in devices:
        all_vulns.extend(devi["vulns"])

    unique_cves = set(all_vulns)

    # scored and ranked cves
    enriched_cves = {}

    print("ranking cves \n")
    for cve_id in unique_cves:
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = requests.get(url, timeout=10)  # Add timeout
            # increased to 6 seconds becuase of api timeout (i think)
            time.sleep(6)
            if response.status_code != 200:
                print(f"HTTP Code {response.status_code} for {cve_id}")
                enriched_cves[cve_id] = {"score": 0.0, "severity": "ERROR"}
                continue  # Skip to next CVE

            data = response.json()

            vuln_list = data.get("vulnerabilities", [])
            if not vuln_list:
                enriched_cves[cve_id] = {"score": 0.0, "severity": "UNKNOWN"}
                continue

            cve = vuln_list[0]["cve"]

            # Try to pull CVSS v3.1 → v3.0 → v2
            metrics = cve.get("metrics", {})
            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]
            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0]["cvssData"]
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]
            else:
                cvss = {"baseScore": 0.0, "baseSeverity": "UNKNOWN"}

            enriched_cves[cve_id] = {
                "score": cvss.get("baseScore", 0.0),
                "severity": cvss.get("baseSeverity", "UNKNOWN"),
            }

        except Exception as e:
            print(f"Error fetching {cve_id}: {e}")
            enriched_cves[cve_id] = {"score": 0.0, "severity": "ERROR"}

    return enriched_cves

    # this will iterate through both dicts and look for the cves. it will then add score from ranked dict to shodan dict


# adds the scored cves to the list
def add_scores_to_devices(devices: list, ranked_cves: dict):
    """Add cumulative CVE scores to each device"""

    print("adding up the scores \n")

    for device in devices:
        total_score = 0
        device_vulns = device.get("vulns", [])

        # Check each CVE in the device's vulns list
        for cve in device_vulns:
            if cve in ranked_cves:
                total_score += ranked_cves[cve]["score"]

        # Add the total score to the device
        device["score"] = total_score

    return devices

    # for device in devices:
    #     vulns = device.get("vulns", {})  # Get the vulns dict from each device
    #     unique_cves.update(vulns.keys())  # Add all CVE IDs to the set

    # return unique_cves  # Returns set of unique CVE strings like {'CVE-2023-1234', 'CVE-2023-5678'}


# thanks gpt, saved me a headache
def print_devices_table(devices):
    """Print devices in a neat table format, sorted by score (highest to lowest)"""
    if not devices:
        print("No devices found.")
        return

    # Sort by score descending (highest to lowest)
    sorted_devices = sorted(devices, key=lambda x: x.get("score", 0), reverse=True)

    print(
        f"\n{'Rank':<5} {'IP Address':<15} {'Port':<6} {'Product':<20} {'CVEs':<5} {'Score':<8} {'Severity'}"
    )
    print("-" * 80)

    for rank, device in enumerate(sorted_devices, 1):
        ip = device.get("ip", "N/A")
        port = str(device.get("port", "N/A"))
        product = device.get("product", "Unknown")[:19]  # shorten if too long
        cve_count = len(device.get("vulns", []))
        score = device.get("score", 0)
        cves = device.get("vulns", [])

        # Determine severity based on score
        if score >= 9.0:
            severity = "CRITICAL"
        elif score >= 7.0:
            severity = "HIGH"
        elif score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        print(
            f"{rank:<5} {ip:<15} {port:<6} {product:<20} {cve_count:<5} {score:<8.1f} {severity} {cves}"
        )


main()


# TEST DICT THAT WORKS
# [
#     {
#         "ip": "192.168.1.101",
#         "port": 22,
#         "transport": "tcp",
#         "org": "Example Corp",
#         "asn": "AS12345",
#         "isp": "ExampleISP",
#         "product": "OpenSSH",
#         "version": "7.9p1",
#         "cpe": ["cpe:/a:openbsd:openssh:7.9"],
#         "os": "Linux",
#         "vulns": [
#             "CVE-1999-0039",
#             "CVE-2017-0144",
#             "CVE-2014-0160",
#             "CVE-2017-5638",
#             "CVE-2022-22965",
#         ],
#         "ssh": {
#             "fingerprint": "SHA256:abcd1234efgh5678ijkl9101mnopqrstuvwx",
#             "cipher": "aes256-ctr",
#             "mac": "hmac-sha2-256",
#         },
#         "city": "New York",
#         "region_code": "NY",
#         "country_name": "United States",
#         "country_code": "US",
#         "latitude": 40.7128,
#         "longitude": -74.0060,
#     }
# ]
