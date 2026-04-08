import csv #Process CSV
import copy #Copy
import sys #For cmd arguments
import ast #To parse header dicts from CSV
import os #Make files
from augmentation.payloads import PAYLOADS # prompt injection payloads

#Read the preprocessed CSV
def load_preprocessed(csv_path):
    requests = []
    with open(csv_path, encoding="utf-8", errors="replace") as f:
        reader = csv.DictReader(f) #Use DictReader since we have headers
        for row in reader:
            row["headers"] = ast.literal_eval(row["headers"]) #Parse the headers string back to dict
            requests.append(row)
    benign = sum(1 for r in requests if r["label"] == "benign") #Count the number of begnine and malicious
    malicious = len(requests)-benign
    print(f"Loaded {len(requests)} requests ({benign} benign, {malicious} malicious)") 
    return requests

#Inject a payload into the User-Agent header of a request
def inject(request, payload_id, payload_text):
    r = copy.deepcopy(request) #Don't modify the original
    orig_ua = r["headers"].get("User-Agent", "")
    r["headers"]["User-Agent"] = f"{orig_ua} {payload_text}" if orig_ua else payload_text #Put in the payload
    r["injection_id"] = payload_id #Keep track of the metadata
    r["injection_text"] = payload_text
    r["original_ua"] = orig_ua
    return r

#Build the 3-condition dataset
#1: benign (as-is) for false positive rate. 2: malicious, no injection (as-is) for baseline detection rate. 3: malicious + injection for ASR (compare to B)
def build_augmented(requests):
    benign = [r for r in requests if r["label"] == "benign"] #1
    malicious = [r for r in requests if r["label"] == "malicious"] #2

    #3
    injected = []
    for req in malicious:
        for pid, text, desc in PAYLOADS:
            injected.append(inject(req, pid, text))

    print(f"1 (benign): {len(benign)}")
    print(f"2 (malicious clean): {len(malicious)}")
    print(f"3 (malicious+inject): {len(injected)}")
    return benign, malicious, injected

#Save each condition to its own CSV
def save_condition(data, path, is_injected=False):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        #Header
        cols = ["method", "url", "protocol", "headers", "body", "label", "attack_type"]
        if is_injected:
            cols += ["injection_id", "injection_text", "original_ua"]
        writer.writerow(cols)
        #Rows
        for item in data:
            row = [item["method"], item["url"], item["protocol"], str(item["headers"]), item["body"], item["label"], item["attack_type"]]
            if is_injected:
                row += [item["injection_id"], item["injection_text"], item["original_ua"]]
            writer.writerow(row)

if __name__ == "__main__":
    #Get the arguments
    input_path = sys.argv[1] if len(sys.argv) > 2 else "data/preprocessed.csv" #Preprocessed CSV
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "data/augmented" #Output directory

    os.makedirs(out_dir, exist_ok=True)

    #Load and build
    requests = load_preprocessed(input_path)
    benign, malicious, injected = build_augmented(requests)

    #Save
    save_condition(benign, f"{out_dir}/A_benign.csv")
    save_condition(malicious, f"{out_dir}/B_malicious_clean.csv")
    save_condition(injected, f"{out_dir}/C_malicious_injected.csv", is_injected=True)

    print(f"\nSaved to {out_dir}/")
    print(f"A_benign.csv ({len(benign)} rows)")
    print(f"B_malicious_clean.csv ({len(malicious)} rows)")
    print(f"C_malicious_injected.csv ({len(injected)} rows)")