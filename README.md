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


Rank  IP Address      Port   Product              CVEs  Score    Severity
--------------------------------------------------------------------------------
1     193.19.177.180  80     nginx                26    156.0    CRITICAL ['CVE-2022-31628', 'CVE-2022-31629', 'CVE-2024-25117', 'CVE-2007-3205', 'CVE-2024-3566', 'CVE-2020-7059', 'CVE-2020-7070', 'CVE-2022-37454', 'CVE-2019-11048', 'CVE-2013-2220', 'CVE-2019-11046', 'CVE-2019-11047', 'CVE-2019-11044', 'CVE-2019-11045', 'CVE-2022-4900', 'CVE-2020-7060', 'CVE-2020-7061', 'CVE-2020-7062', 'CVE-2020-7063', 'CVE-2020-7064', 'CVE-2020-7066', 'CVE-2020-7067', 'CVE-2020-7068', 'CVE-2020-7069', 'CVE-2017-8923', 'CVE-2019-11050']
2     47.90.121.53    80     nginx                12    87.8     CRITICAL ['CVE-2023-44487', 'CVE-2017-7529', 'CVE-2017-20005', 'CVE-2019-9516', 'CVE-2019-9513', 'CVE-2019-9511', 'CVE-2018-16843', 'CVE-2021-23017', 'CVE-2021-3618', 'CVE-2019-20372', 'CVE-2018-16844', 'CVE-2018-16845']
3     88.198.109.183  80     nginx                12    87.8     CRITICAL ['CVE-2023-44487', 'CVE-2017-7529', 'CVE-2017-20005', 'CVE-2019-9516', 'CVE-2019-9513', 'CVE-2019-9511', 'CVE-2018-16843', 'CVE-2021-23017', 'CVE-2021-3618', 'CVE-2019-20372', 'CVE-2018-16844', 'CVE-2018-16845']
4     36.99.116.165   80     nginx                10    70.5     CRITICAL ['CVE-2023-44487', 'CVE-2019-9516', 'CVE-2019-9513', 'CVE-2019-9511', 'CVE-2018-16843', 'CVE-2021-23017', 'CVE-2021-3618', 'CVE-2019-20372', 'CVE-2018-16844', 'CVE-2018-16845']
5     58.154.205.21   80     nginx                8     55.5     CRITICAL ['CVE-2023-44487', 'CVE-2019-9516', 'CVE-2019-9513', 'CVE-2019-9511', 'CVE-2021-23017', 'CVE-2021-3618', 'CVE-2019-20372', 'CVE-2018-16845']
6     156.229.103.61  80     nginx                6     37.8     CRITICAL ['CVE-2013-2220', 'CVE-2025-6491', 'CVE-2025-1220', 'CVE-2025-1735', 'CVE-2007-3205', 'CVE-2024-3566']
7     114.7.28.11     80     nginx                3     22.6     CRITICAL ['CVE-2023-44487', 'CVE-2021-23017', 'CVE-2021-3618']
8     88.198.223.143  80     nginx                3     22.6     CRITICAL ['CVE-2023-44487', 'CVE-2021-23017', 'CVE-2021-3618']
9     212.111.41.208  80     nginx                0     0.0      LOW []
10    50.17.29.60     80     nginx                0     0.0      LOW []
11    43.100.134.223  80     nginx                0     0.0      LOW []
12    158.201.226.61  80     nginx                0     0.0      LOW []
13    141.94.154.246  80     nginx                0     0.0      LOW []
14    147.182.252.79  80     nginx                0     0.0      LOW []
15    92.53.118.195   80     nginx                0     0.0      LOW []
16    154.210.241.199 80     nginx                0     0.0      LOW []
17    91.184.31.246   80     nginx                0     0.0      LOW []
18    59.36.188.66    80     nginx                0     0.0      LOW []
19    104.131.12.198  80     nginx                0     0.0      LOW []
20    154.210.80.77   80     nginx                0     0.0      LOW []
21    8.130.15.67     80     nginx                0     0.0      LOW []
22    38.207.74.241   80     nginx                0     0.0      LOW []
23    45.132.107.84   80     nginx                0     0.0      LOW []
24    219.231.172.137 80     nginx                0     0.0      LOW []
25    40.127.106.117  80     nginx                0     0.0      LOW []
26    154.31.131.152  80     nginx                0     0.0      LOW []
27    103.60.148.171  80     nginx                0     0.0      LOW []
28    104.221.131.6   80     nginx                0     0.0      LOW []
29    46.105.141.124  80     nginx                0     0.0      LOW []
30    104.248.22.39   80     nginx                0     0.0      LOW []