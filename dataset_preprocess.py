import csv #Process CSV
import re #Regex
import random #Randomness
import sys #For cmd arguments
from urllib.parse import unquote #Decode URL-encoded strings
from urllib.parse import urlparse #Parse URL
from collections import Counter


#The following signiture patterns were made by ChatGPT when prompted to make regex patterns for SQL Injection, Cross Site Scripting, or Command Injection
SIGS = {
    "sqli": re.compile(r"(UNION\s+SELECT|DROP\s+TABLE|SELECT\s+\*|OR\s+1\s*=\s*1|INSERT\s+INTO|'\s*;\s*SELECT|'\s*OR\s*')", re.I),
    "xss":  re.compile(r"(<script|<img\s[^>]*onerror|javascript\s*:|alert\s*\(|<svg\s[^>]*onload|document\.cookie)", re.I),
    "cmdi": re.compile(r"(;\s*(cat|ls|whoami|rm|wget|curl|id)\s|exec\s+cmd|\|\s*(cat|ls|whoami)|/etc/passwd)", re.I),
}

#Classify a row as malicious or clean
def classify(row):
    if len(row) < 16:
        return None #Skip rows that are too short
    is_normal = row[0].strip().lower() == "normal" #First column is 0 for benign
    url = row[16].strip()  #URL
    body = row[14].strip() #HTTP Body
    text = unquote(f"{url} {body}") #Combine and URL decode URL and body

    if is_normal:
        for pat in SIGS.values():
            if pat.search(text):
                return None  #If it is benign, make sure it does not match any attack patterns. 
        label, attack_type = "benign", "" #Label as benign
    else:
        attack_type = None
        for name, pattern in SIGS.items(): #If it is malicious, make sure it follows an attack pattern.
            if pattern.search(text):
                attack_type = name
                break
        if attack_type is None:
            return None  #Skip (we are not doing obfuscation/fuzzing/tampering)
        label = "malicious" #Label it as malicious

    ###The rest of the code up to the return statement was written by ChatGPT to parse the HTTP information and create the sample.
    parsed = urlparse(url)
    path = parsed.path
    if parsed.query:
        path += "?" + parsed.query
    headers = {}
    for i, name in [(2,"User-Agent"),(3,"Pragma"),(4,"Cache-Control"),(5,"Accept"), (6,"Accept-Encoding"),(7,"Accept-Charset"),(8,"Accept-Language"), (9,"Host"),(10,"Cookie"),(11,"Content-Type"),(12,"Connection")]:
        if len(row) > i and row[i].strip():
            headers[name] = row[i].strip()
    if len(row) > 13 and row[13].strip():
        headers["Content-Length"] = row[13].strip()

    #Return everything
    return label, attack_type, {
        "method": row[1].strip(),
        "url": path or "/",
        "protocol": parsed.scheme,
        "headers": headers,
        "body": body,
        "label": label,
        "attack_type": attack_type,
    }
    ###End of ChatGPT code

def load_clean(csv_path, n=100):
    benign = []
    malicious = []
    malicious_by_type = {k: [] for k in SIGS.keys()}

    #Read the file
    with open(csv_path, encoding="utf-8", errors="replace") as f:
        for row in csv.reader(f):
            result = classify(row) #Classify the row
            if result is None: 
                continue
            label = result[0] #Get the label
            data = result[2] #And data
            #Add it to the right list

            if label == "benign":
                benign.append(data)
            else:
                malicious.append(data)
                if data["attack_type"] in malicious_by_type:
                    malicious_by_type[data["attack_type"]].append(data)

    random.seed(42)

    #Get a random sample
    benign_sample = random.sample(benign, min(n, len(benign)))
    attack_types = list(malicious_by_type.keys())
    per_type = max(1, n // len(attack_types))  # split evenly

    malicious_sample = []

    for attack_type, items in malicious_by_type.items():
        sample_size = min(per_type, len(items))
        malicious_sample.extend(random.sample(items, sample_size))

    #Print the resutls
    print("Clean:", len(benign), "benign,", len(malicious), "malicious")
    print("Sampled:", len(benign_sample), "+", len(malicious_sample))

    return benign_sample + malicious_sample #Read the results

def save_to_csv(data, out_path):
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        #Header row
        writer.writerow([
            "method", "url", "protocol",
            "headers", "body",
            "label", "attack_type"
        ])

        #Everything else
        for item in data:
            writer.writerow([
                item["method"],
                item["url"],
                item["protocol"],
                str(item["headers"]),  # store as string
                item["body"],
                item["label"],
                item["attack_type"]
            ])

if __name__ == "__main__":
    #Get the arguments
    path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else "output.csv"
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 100
    
    #Load the data
    data = load_clean(path, n)

    #Save it 
    save_to_csv(data, out_path)

    #Print the results
    counts = Counter()
    for item in data:
        if item["attack_type"]:
            counts[item["attack_type"]] += 1
    print("Saved to:", out_path)
    print("Attack types:", dict(counts))
