import requests

headers = {
    "accept": "application/json",
    "x-apikey": "d7d63a96bf75a2f6be386d5d0eb25c05dd15fe14f70a7776df2d7a7f21fcb76e"
}

# Hardcode the file path
filepath = "sha1_list.txt"

with open(filepath, 'r') as f:
    for line in f:
        file_hash_id = line.strip()  # (SHA-256, SHA-1 or MD5 identifying the file)
        url = "https://www.virustotal.com/api/v3/files/" + file_hash_id

        try:
            response = requests.get(url, headers=headers)
            convertedHash = response.json()
            print(convertedHash["data"]["attributes"]["sha256"])
        except Exception as e:
            print("hash not found at VirusTotal")