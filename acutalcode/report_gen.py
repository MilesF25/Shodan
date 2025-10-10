import requests
import time
import os
import textwrap


# test dict
d = {
    "ip": "146.71.125.142",
    "port": 27017,
    "transport": "tcp",
    "org": "GorillaServers, Inc.",
    "asn": "AS53850",
    "isp": "GorillaServers, Inc.",
    "product": "MongoDB",
    "version": "4.4.29",
    "cpe": ["cpe:/a:mongodb:mongodb:4.4.29", "cpe:/a:openssl:openssl:1.1.1f"],
    "os": "null",
    "vulns": [
        "CVE-2022-0778",
        "CVE-2022-2097",
        "CVE-2020-1971",
        "CVE-2022-4304",
        "CVE-2009-1390",
        "CVE-2023-5678",
        "CVE-2022-2068",
        "CVE-2009-3766",
        "CVE-2022-1292",
        "CVE-2009-3765",
        "CVE-2019-0190",
        "CVE-2021-3711",
        "CVE-2024-0727",
        "CVE-2021-3712",
        "CVE-2023-0464",
        "CVE-2023-0465",
        "CVE-2023-0466",
        "CVE-2021-3449",
        "CVE-2021-23840",
        "CVE-2021-23841",
        "CVE-2022-4450",
        "CVE-2023-0286",
        "CVE-2023-3817",
        "CVE-2023-4807",
        "CVE-2020-1967",
        "CVE-2021-4160",
        "CVE-2023-2650",
        "CVE-2023-0215",
        "CVE-2009-3767",
    ],
}


def string_maker(info: dict) -> dict:
    # will look for the actual null word and make it a "null"
    for key, value in info.items():
        if value == "null":
            info[key] = "null"


def realc(info: dict):
    """
    Enrich CVE data with scores, severity, and descriptions from NVD
    """
    enriched_cves = {}
    print(info)

    for cve_id in info["vulns"]:
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = requests.get(url, timeout=10)

            # Rate limiting (6 seconds between requests)
            time.sleep(6)

            if response.status_code != 200:
                print(f"HTTP Code {response.status_code} for {cve_id}")
                enriched_cves[cve_id] = {
                    "score": 0.0,
                    "severity": "ERROR",
                    "description": "Failed to fetch data",
                }
                continue

            data = response.json()

            vuln_list = data.get("vulnerabilities", [])
            if not vuln_list:
                enriched_cves[cve_id] = {
                    "score": 0.0,
                    "severity": "UNKNOWN",
                    "description": "No vulnerability data available",
                }
                continue

            cve = vuln_list[0]["cve"]

            # Extract description
            description = "No description available"
            descriptions = cve.get("descriptions", [])
            if descriptions:
                description = descriptions[0].get("value", "No description available")

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
                "description": description,
            }

        except Exception as e:
            print(f"Error fetching {cve_id}: {e}")
            enriched_cves[cve_id] = {
                "score": 0.0,
                "severity": "ERROR",
                "description": f"Error: {str(e)}",
            }

    return enriched_cves


def info_print(enriched_cve: dict, info: dict):
    # will rank by severity and score
    print(render_info_string(enriched_cve, info))


def render_info_string(enriched_cve: dict, info: dict) -> str:
    """Return the full report as a single string (same format as info_print)."""
    lines = []
    lines.append("\n" + "=" * 55)
    lines.append(
        f"Threat Model Report for: {info['ip']}:{info['port']} ({info['product']})"
    )
    lines.append("=" * 55)
    lines.append("")

    # Print discovered cpe
    lines.append("Discovered CPEs:")
    for cpe in info.get("cpe", []):
        lines.append(f"- Discovered CPE: {cpe} \n")

    # CVE print
    lines.append("Associated Vulnerabilities:")
    for cve_id, details in enriched_cve.items():
        severity = details["severity"]
        lines.append(f"- {cve_id} (Severity: {severity})")

    lines.append("\n" + "=" * 70)
    lines.append("--- POTENTIAL ATTACK PATHS (Ranked by Severity) ---")
    lines.append("=" * 70 + "\n")

    if not enriched_cve:
        lines.append("No vulnerabilities found")
        return "\n".join(lines)

    # Define severity ranking (higher number = more severe)
    severity_rank = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "UNKNOWN": 0,
        "ERROR": -1,
    }

    # Sort CVEs by severity (primary) and score (secondary)
    sorted_cves = sorted(
        enriched_cve.items(),
        key=lambda x: (
            severity_rank.get(x[1]["severity"], 0),  # Sort by severity first
            x[1]["score"],  # Then by score
        ),
        reverse=True,  # Highest first
    )

    # Add each CVE
    for rank, (cve_id, details) in enumerate(sorted_cves, 1):
        severity = details["severity"]
        score = details["score"]
        description = details.get("description", "No description available")

        # Add the CVE header
        lines.append(f"{rank}. {cve_id}, Severity: {severity} (Score: {score}/10):")

        # Wrap the description properly
        wrapped_description = textwrap.fill(
            description, width=70, initial_indent="   ", subsequent_indent="   "
        )

        lines.append(wrapped_description)
        lines.append("")  # Blank line between CVEs

    return "\n".join(lines)


def write_info_to_file(enriched_cve: dict, info: dict, filename: str):
    """Write the rendered report to `filename` (text file)."""
    content = render_info_string(enriched_cve, info)
    with open(filename, "w", encoding="utf-8") as f:
        f.write(content)


def uniquify(path):
    filename, extension = os.path.splitext(path)
    counter = 1

    while os.path.exists(path):
        path = filename + " (" + str(counter) + ")" + extension
        counter += 1

    return path


def save_filename(filename="devices_info.txt"):
    ans = input(
        "Would you like to name the csv something other than devices_info.txt? yes/no: "
    )

    if ans.lower() == "yes" or ans.lower() == "y":
        filename = input("Enter your desired filename (with .txt extension): ").strip()

        if not filename.endswith(".txt"):
            filename += ".txt"
    else:
        filename = "devices_info.txt"
    if os.path.exists(filename):
        new_file = uniquify(filename)
        return new_file
    else:
        return filename


# takes a dict
def combined(scan_info: dict) -> str:
    # this will fix the null values in the dict
    # fixed_dict_values = string_maker(scan_info)
    # print(f"fixed: {fixed_dict_values}")
    # enriched cve, d is the original dict
    calculated_cve_dict = realc(scan_info)

    # this will print the info to the terminal
    info_print(calculated_cve_dict, scan_info)

    # also write the report to a uniquely-named txt file
    # file output name
    out_name = save_filename()
    # just checks to see if the file exists, if it does it makes a new file with a (1) at the end
    unique_out = uniquify(out_name)
    # write to file
    write_info_to_file(calculated_cve_dict, scan_info, unique_out)
