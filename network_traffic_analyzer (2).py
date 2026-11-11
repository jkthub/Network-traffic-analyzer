import csv
from collections import Counter

print("==============================================")
print("          NETWORK TRAFFIC ANALYZER")
print("==============================================")

protocols = Counter()
sources = Counter()
destinations = Counter()
suspicious = []

# Read sample network traffic
with open("traffic.csv", "r") as file:
    reader = csv.DictReader(file)

    for row in reader:
        protocols[row["Protocol"]] += 1
        sources[row["Source_IP"]] += 1
        destinations[row["Destination_IP"]] += 1

        # Check commonly suspicious ports
        if int(row["Destination_Port"]) in [21, 23, 445, 3389, 4444]:
            suspicious.append(row)

print("\nProtocol Summary")
for protocol, count in protocols.items():
    print(protocol, ":", count, "packets")

print("\nTop Source IP Addresses")
for ip, count in sources.most_common(3):
    print(ip, ":", count, "packets")

print("\nTop Destination IP Addresses")
for ip, count in destinations.most_common(3):
    print(ip, ":", count, "packets")

print("\nSuspicious Port Activity")
if suspicious:
    for row in suspicious:
        print(row["Source_IP"], "->", row["Destination_IP"],
              ": Port", row["Destination_Port"])
else:
    print("No suspicious activity detected.")

print("\nAnalysis completed successfully.")
