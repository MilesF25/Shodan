import shodan
import nvdlib
from collections import Counter
from rich.console import Console
from rich.table import Table


def main():
    api_key = input("Enter your Shodan API key: ").strip()
    api = shodan.Shodan(api_key)  # use user key
    console = Console()

    query = input("Enter the rest of your Shodan query: ")

    og_query = city_report(query, api, console)
    extract_shodan_match(og_query)


def city_report(usr_query: str, api, console):
    query = usr_query
    print(f"[*] Running query: {query}")

    try:
        results = api.search(query, limit=40)  # first 200 results
    except shodan.APIError as e:
        print(f"[!] Shodan API Error: {e}")

    return results


def extract_shodan_match(results: dict) -> dict:
    """
    Extracts useful fields from a Shodan host match safely.
    Always returns a dict with consistent keys.
    """
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


# Next step is to figure out how rank all the queries. I need to rank by most sever
main()


# def display(results: dict):


# risk_score = calculate_vuln_score(device)
