# Shodan
This tool uses Shodan to automate the discovery, enrichment, and risk assessment of exposed devices on the internet. The solution collects device data, extracts and ranks vulnerabilities (CVEs), and generates clear reports, including CSV and JSON exports, enabling efficient cybersecurity analysis and decision-making. (hopefully for good)


## How it works

This program works by entering a normal shodan query

There is a example of how to use the tool when you run it. This is the link the official search query docs. https://www.shodan.io/search/examples

# Pip Install requirments

- pip install shodan rich


# IMPORTANT

- YOU WILL NEED AN API KEY, THE FREE KEY DOES NOT WORK WITH PYTHON API

- It will take some time to run. I'm using NIST api to score the CVEs. Thats why the amount returned is limited to 40, and there is a 6 second pause between each request. Don't want it to look like an attack

- NOT ALL QUERIES WILL RETURN CVEs



# Example Output

Enter your Shodan API key: 

Enter the rest of your Shodan query: product:nginx port:80
[*] Running query: product:nginx port:80
ranking cves 

adding up the scores 


![screenshot](Screenshot 2025-09-11 170257.png)