import requests
import json

def test_questions():
    url = "http://localhost:8000/ask"
    
    questions = [
        "How many total sales records do we have?",
        "What is the total revenue by product?",
        "Which region has the highest sales?",
        "What is the average order quantity?"
    ]
    
    for question in questions:
        print(f"\nTesting Question: {question}")
        try:
            response = requests.post(url, json={"text": question})
            result = response.json()
            print("\nResponse:")
            print(json.dumps(result, indent=2))
        except Exception as e:
            print(f"Error: {str(e)}")
        print("-" * 80)

if __name__ == "__main__":
    test_questions()