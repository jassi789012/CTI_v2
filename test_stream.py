import requests
import json

url = "http://localhost:8000/api/chats/test_123/message"
payload = {"message": "Hi, answer in one sentence."}
headers = {"Content-Type": "application/json"}

response = requests.post(url, json=payload, stream=True)

print(f"Status Code: {response.status_code}")
for line in response.iter_lines():
    if line:
        print(line.decode('utf-8'))
