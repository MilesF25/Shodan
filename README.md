# Shodan
This tool uses Shodan to automate the discovery, enrichment, and risk assessment of exposed devices on the internet. The solution collects device data, extracts and ranks vulnerabilities (CVEs), and generates clear reports, including CSV and JSON exports, enabling efficient cybersecurity analysis and decision-making. (hopefully for good)


## How it works

This program works by entering a normal shodan query

There is a example of how to use the tool when you run it. This is the link the official search query docs. https://www.shodan.io/search/examples

# Pip Install requirments

- pip install shodan rich


# IMPORTANT

YOU WILL NEED AN API KEY, THE FREE KEY DOES NOT WORK WITH PYTHON API


# Example Output

Enter your Shodan API key: 
Would you like to use example query (yes/no)? yes

Select an example query:
1. port:80 country:US apache
2. nginx city:"Los Angeles" port:443
3. microsoft-iis country:DE port:80
4. port:22 openssh country:US
5. apache port:80 org:"Amazon"
Enter number (1-5): 5
Selected query: apache port:80 org:"Amazon"
[*] Running query: apache port:80 org:"Amazon"
   Top CVEs in   
 apache port:80  
  org:"Amazon"   
┏━━━━━━━━━━━━━━━┓
┃ CVE           ┃
┡━━━━━━━━━━━━━━━┩
│ CVE-2013-0941 │
│ CVE-2013-4365 │
│ CVE-2012-4001 │
│ CVE-2009-2299 │
│ CVE-2013-2765 │
└───────────────┘
               Most Exposed Orgs                
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Org                                  ┃ Hosts ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Amazon Technologies Inc.             │ 79    │
│ Amazon Data Services NoVa            │ 30    │
│ Amazon Data Services Japan           │ 26    │
│ Amazon Data Services Ireland Limited │ 19    │
│ Amazon Data Services India           │ 13    │
└──────────────────────────────────────┴───────┘
             Exposed Services
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━┓
┃ Service                         ┃ Hosts ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━┩
│ Apache httpd                    │ 178   │
│ Apache Tomcat/Coyote JSP engine │ 2     │
│ Apache Superset                 │ 1     │
│ Nextcloud                       │ 1     │
└─────────────────────────────────┴───────┘




# Digging Deep

I have completed the deeper analysis of this project. 