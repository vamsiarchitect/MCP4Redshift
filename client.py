# client.py
import requests
import json
from typing import Dict, Any

class RedshiftQAClient:
    def __init__(self, server_url="http://localhost:8000"):
        self.server_url = server_url

    def ask_question(self, question: str) -> Dict[str, Any]:
        try:
            response = requests.post(
                f"{self.server_url}/ask",
                json={"text": question}
            )
            return response.json()
        except Exception as e:
            return {"error": str(e)}

    def print_response(self, response: Dict[str, Any]) -> None:
        print("\n" + "="*80)
        
        if "error" in response:
            print(f"Error: {response['error']}")
            return
            
        if isinstance(response.get('response'), dict):
            result = response['response']
            if 'sql_query' in result:
                print(f"SQL Query: {result['sql_query']}")
            if 'results' in result:
                print("\nResults:")
                print(result['results'])
            if 'answer' in result:
                print("\nAnswer:")
                print(result['answer'])
        else:
            print("Response:")
            print(json.dumps(response, indent=2))
            
        print("="*80)

    def run_test_questions(self) -> None:
        test_questions = [
            "Show me total sales for each product",
            "What's the total revenue and quantity for each product?",
            "Which region has the highest sales?",
            "What's the average order value for each product?"
        ]

        print("\nRunning test questions:")
        for question in test_questions:
            print(f"\nQuestion: {question}")
            response = self.ask_question(question)
            self.print_response(response)

    def interactive_mode(self) -> None:
        print("\nWelcome to Redshift QA System!")
        print("Commands:")
        print("  'exit' to quit")
        print("  'test' to run test questions")
        print("  'help' to see sample questions")

        sample_questions = [
            "Show me total sales for each product",
            "What's the total revenue for Tablet?",
            "Compare sales between Laptop and Smartphone",
            "What's the average order value for each product?",
            "Show me monthly sales for Headphones"
        ]

        # Show initial product information
        print("\nGetting available products...")
        response = self.ask_question("List all distinct products with their total sales")
        self.print_response(response)

        while True:
            try:
                command = input("\nEnter your question (or command): ").strip()
                
                if command.lower() == 'exit':
                    print("Goodbye!")
                    break
                elif command.lower() == 'test':
                    self.run_test_questions()
                elif command.lower() == 'help':
                    print("\nSample questions you can ask:")
                    for q in sample_questions:
                        print(f"- {q}")
                else:
                    response = self.ask_question(command)
                    self.print_response(response)
            except Exception as e:
                print(f"\nError processing request: {str(e)}")

def main():
    client = RedshiftQAClient()
    
    print("\nRedshift QA Client")
    print("1. Interactive Mode")
    print("2. Run Test Questions")
    print("3. Exit")
    
    while True:
        try:
            choice = input("\nEnter your choice (1-3): ")
            
            if choice == '1':
                client.interactive_mode()
                break
            elif choice == '2':
                client.run_test_questions()
                break
            elif choice == '3':
                print("Goodbye!")
                break
            else:
                print("Invalid choice. Please enter 1, 2, or 3.")
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except Exception as e:
            print(f"\nError: {str(e)}")

if __name__ == "__main__":
    main()