# Shodan Exposure Analyzer

A toolkit for discovering and analyzing exposed services using Shodan. It queries Shodan, pulls host details, enriches CVEs through NVD, ranks hosts by their cumulative CVSS scores, and generates reports in CSV, JSON, and readable text formats.

The repo has three main modules:
- `deep_analysis.py` — runs Shodan queries, compiles device data, enriches CVEs, calculates per-device scores, and exports to CSV/JSON
- `main.py` — interactive CLI to either run a scan or generate a report from saved JSON data
- `report_gen.py` — creates a readable threat model report for a single host with CVE severity, scores, and descriptions


## Features
- Shodan search and device extraction (IP, port, product, OS, org, CPEs, location, etc.)
- Vulnerability aggregation per device (CVE IDs)
- NVD enrichment (score, severity, description) with rate limiting
- Per-device cumulative score (sum of CVSS base scores for all CVEs on that device)
- CSV export (one row per host/CVE) with the original Shodan query at the top
- JSON export (raw device list) for later reporting
- Per-host report generator with severity-ranked attack paths
- Interactive prompts to pick saved JSON files and hosts to report on


## Requirements
- Python 3.10+
- Shodan API key (paid plan typically required for API access)
- Internet connection for Shodan and NVD APIs

Install dependencies:
```bash
pip install -r requirements.txt
```


## Installation
1. Create and activate a virtual environment (optional but recommended)

2. Install dependencies
```bash
pip install -r requirements.txt
```


## Usage

### Interactive CLI
```bash
python main.py
```
Choose "Scan" to run a Shodan search and export results, or "Report" to generate a host report from saved JSON.




## How it works

### Scan workflow
When you run a scan, it will:
1. Prompt for your Shodan API key and query (e.g., `product:nginx port:80`)
2. Execute the search (limited to reduce API costs)
3. Extract relevant device info
4. Collect unique CVE IDs and enrich them via NVD (6-second delay per request for rate limiting)
5. Calculate cumulative CVSS scores per device
6. Print a ranked table of devices
7. Offer to export results to CSV and JSON with unique filenames

### Report workflow
When you generate a report:
1. The program lists available `.json` files in the current directory (generated from previous scans)
2. You pick one and select a host from the ranked menu
3. A text report gets generated and saved to a `.txt` file


## Output files
- `device_info_dump.json` — JSON array with one object per device including IP, port, org, product, OS, CPE, and CVEs
- `devices_info.csv` — CSV with columns `[ip, port, org, product, os, cve]`; includes the original query at the top; each CVE gets its own row per device
- `devices_info.txt` — Per-host report showing discovered CPEs and CVEs, ranked by severity and score, with descriptions


## Example workflow

**1. Run a scan:**
```bash
python main.py
```
- Select "Scan"
- Enter your Shodan API key
- Enter a query (e.g., `product:nginx port:80`)
- Wait for enrichment to finish and review the ranked table
- Choose to export CSV/JSON

**2. Generate a report:**
```bash
python main.py
```
- Select "Report"
- Pick the JSON file from step 1
- Select a host from the menu
- Report gets saved as `devices_info.txt`


## Notes
- Shodan API usage depends on your plan and token limits. Keep queries reasonable.
- NVD API has rate limits. The code uses a 6-second sleep between requests, so large CVE sets will take time.
- Not all Shodan results include CVEs. Devices without CVEs will show a score of 0 and export with `cve=None` in the CSV.


## Module breakdown

**`deep_analysis.py`:**
- `city_report`: wraps Shodan API search
- `extract_shodan_match`: extracts structured device fields
- `calc`: enriches CVEs via NVD and returns CVE→score/severity mapping
- `add_scores_to_devices`: sums CVE scores per device
- `print_devices_table`: prints ranked device table
- `save_output`/`json_dump_format`: export to CSV/JSON with unique filenames

**`main.py`:**
- Interactive menu for Scan or Report
- Scan delegates to `deep_analysis`
- Report loads saved JSON, lets you select a host, calls `report_gen.combined`

**`report_gen.py`:**
- `realc`: enriches a single host's CVEs with score, severity, description
- `render_info_string`: builds readable report ranked by severity then score
- `write_info_to_file`: saves report to text file


## Troubleshooting
- **Shodan API Error:** Make sure your API key is valid and has the right permissions. Free keys usually don't work with the Python API.
- **No JSON files found:** Run a scan first to generate `device_info_dump.json`.
- **Long runtime:** CVE enrichment uses delays to respect NVD rate limits. This is expected for large result sets.


## Future ideas
- Cache and batch NVD queries to reduce runtime
- Track highest individual CVE score per device
- HTML/PDF report export
- Configurable search limits and parallel enrichment with rate control


## Legal stuff
Only use this tool on assets you own or have permission to assess. Follow Shodan and NVD terms of service and applicable laws.


## Credits
- Shodan (shodan.io)
- NVD (nvd.nist.gov)
- Rich, Questionary, InquirerPy for terminal UI and formatting