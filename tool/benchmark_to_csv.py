import json
import csv
import sys

if len(sys.argv) < 2:
    print("Usage: python benchmark_to_csv.py [path_to_json_file]")
    sys.exit(1)

json_file_path = sys.argv[1]
csv_file_path = json_file_path.rsplit('.', 1)[0] + '.csv'

with open(json_file_path, 'r') as json_file:
    data = json.load(json_file)

with open(csv_file_path, 'w', newline='') as csv_file:
    fieldnames = ['description', 'numCalls', 'microseconds', 'bytesPerCall']
    writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

    writer.writeheader()

    for entry in data:
        if 'bytesPerCall' not in entry:
            entry['bytesPerCall'] = None
        writer.writerow(entry)

print(f"Data has been converted to CSV and saved as {csv_file_path}")