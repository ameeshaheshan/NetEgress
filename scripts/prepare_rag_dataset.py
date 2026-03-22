import csv
import json
import os
from pathlib import Path

def prepare_dataset(csv_path, payloads_dir, output_path):
    ssrf_data = []
    
    # 1. Process Exploit-DB CSV
    print(f"Filtering {csv_path} for SSRF...")
    keywords = ["ssrf", "server-side request forgery", "server side request forgery"]
    
    try:
        with open(csv_path, 'r', encoding='utf-8') as f:
            # Exploit-DB CSV format: id,file,description,date,author,type,platform,port
            reader = csv.DictReader(f)
            for row in reader:
                description = row.get('description', '').lower()
                if any(k in description for k in keywords):
                    ssrf_data.append({
                        "source": "exploit-db",
                        "id": row.get('id', 'N/A'),
                        "title": row.get('description', 'N/A'),
                        "type": row.get('type', 'N/A'),
                        "platform": row.get('platform', 'N/A'),
                        "content": f"Exploit for {row.get('description')}. Platform: {row.get('platform')}. Type: {row.get('type')}."
                    })
    except Exception as e:
        print(f"Error reading CSV: {e}")

    # 2. Process Local Payloads
    print(f"Processing payloads in {payloads_dir}...")
    payload_mapping = {
        "cloud_metadata.txt": {"technique": "Cloud Metadata", "target": "AWS/Azure/GCP"},
        "dns_rebinding.txt": {"technique": "DNS Rebinding", "target": "Internal Network"},
        "local_ips.txt": {"technique": "Internal Scanning", "target": "Localhost/Intranet"},
        "oob_dns.txt": {"technique": "Out-of-band (OOB)", "target": "External DNS Interactor"},
        "waf_bypass.txt": {"technique": "WAF Bypass", "target": "Hardened Perimeter"}
    }
    
    for filename in os.listdir(payloads_dir):
        if filename.endswith(".txt"):
            file_path = Path(payloads_dir) / filename
            metadata = payload_mapping.get(filename, {"technique": "General SSRF", "target": "Unknown"})
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                ssrf_data.append({
                    "source": "local-payload",
                    "filename": filename,
                    "technique": metadata["technique"],
                    "target": metadata["target"],
                    "content": content
                })

    # 3. Add Technical Documentation (Cloud Metadata)
    print("Adding Cloud Metadata documentation...")
    cloud_docs = [
        {
            "source": "docs",
            "title": "AWS IMDSv1 vs IMDSv2",
            "technique": "Cloud Metadata",
            "target": "AWS",
            "content": "Instance Metadata Service (IMDS) allows EC2 instances to access metadata. IMDSv1 is vulnerable to SSRF as it uses simple GET requests. IMDSv2 requires a Session Token (PUT request) to mitigate SSRF. SSRF against 169.254.169.254 can leak IAM roles."
        },
        {
            "source": "docs",
            "title": "Azure Instance Metadata Service",
            "technique": "Cloud Metadata",
            "target": "Azure",
            "content": "Azure IMDS is available at 169.254.169.254. All requests must include the 'Metadata: true' header to prevent SSRF. It provides info about the instance, network, and managed identities."
        },
        {
            "source": "docs",
            "title": "Google Cloud Metadata Server",
            "technique": "Cloud Metadata",
            "target": "GCP",
            "content": "GCP Metadata is at metadata.google.internal (169.254.169.254). Requires 'Metadata-Flavor: Google' header. SSRF can be used to exfiltrate service account tokens."
        }
    ]
    ssrf_data.extend(cloud_docs)

    # 4. Save Dataset
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(ssrf_data, f, indent=2)
    
    print(f"Dataset created with {len(ssrf_data)} entries at {output_path}")

def query_dataset(query, dataset_path):
    """Simple keyword-based similarity search (Pre-Vector DB)"""
    with open(dataset_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    query = query.lower()
    results = []
    
    for entry in data:
        score = 0
        content = entry.get('content', '').lower()
        title = entry.get('title', '').lower()
        
        # Simple scoring
        if query in title: score += 10
        if query in content: score += 5
        
        if score > 0:
            results.append((score, entry))
    
    # Sort by score
    results.sort(key=lambda x: x[0], reverse=True)
    return results[:3]

if __name__ == "__main__":
    base_dir = r"c:\Users\User\OneDrive\Desktop\Final Project\SSRF Automation"
    dataset_file = os.path.join(base_dir, "knowledge_base", "ssrf_rag_dataset.json")
    
    prepare_dataset(
        os.path.join(base_dir, "CVE", "db.csv"),
        os.path.join(base_dir, "payloads"),
        dataset_file
    )
    
    # Test Search
    print("\n--- Testing Retrieval (Query: 'AWS Metadata') ---")
    matches = query_dataset("AWS Metadata", dataset_file)
    for score, match in matches:
        print(f"[{match['source']}] {match.get('title', match.get('filename'))} (Score: {score})")
