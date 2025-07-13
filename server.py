from langchain_community.utilities import SQLDatabase
from langchain_aws import BedrockLLM
from langchain.chains import create_sql_query_chain
from langchain.prompts.prompt import PromptTemplate
import boto3
import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from dotenv import load_dotenv
import psycopg2
from typing import Any, List, Dict

load_dotenv()

class RedshiftDatabase:
    def __init__(self):
        self.host = os.getenv('REDSHIFT_HOST')
        self.password = os.getenv('REDSHIFT_PASSWORD')
        self.connection = None
        
    def connect(self):
        if not self.connection:
            self.connection = psycopg2.connect(
                host=self.host,
                database='sales_db',
                user='admin',
                password=self.password,
                port=5439
            )
        return self.connection
    
    def run(self, query: str) -> List[tuple]:
        conn = self.connect()
        try:
            with conn.cursor() as cur:
                cur.execute(query)
                if query.strip().lower().startswith('select'):
                    return cur.fetchall()
                conn.commit()
                return []
        except Exception as e:
            conn.rollback()
            raise e

    def get_table_info(self) -> str:
        return """
        Table: sales
        Columns:
        - Date (DATE)
        - Product (VARCHAR)
        - Region (VARCHAR)
        - Quantity (INTEGER)
        - Unit_Price (DECIMAL)
        - Total_Amount (DECIMAL)
        """

class RedshiftQAServer:
    def __init__(self):
        # Initialize Bedrock
        bedrock_client = boto3.client(
            service_name='bedrock-runtime',
            region_name='us-west-2'  # change if your region is different
        )

        # Initialize Bedrock LLM
        self.llm = BedrockLLM(
            client=bedrock_client,
            model_id="anthropic.claude-v2",
            model_kwargs={
                "temperature": 0,
                "max_tokens_to_sample": 2000,
            }
        )

        # Initialize custom Redshift database
        self.db = RedshiftDatabase()

        # Custom prompt template
        self.prompt = PromptTemplate(
            template="""Given an input question, create a syntactically correct PostgreSQL query to run against a database of sales records.
            Important notes:
            1. The Product column is case-sensitive
            2. Product names are: 'Laptop', 'Smartphone', 'Tablet', 'Headphones', 'Smartwatch'
            3. Always use exact product names with correct capitalization
            The table schema is:sales(Date DATE, Product VARCHAR(50), Region VARCHAR(50), Quantity INTEGER, Unit_Price DECIMAL(10,2), Total_Amount DECIMAL(10,2))
            Question: {question}
            Return only the SQL query, nothing else.
            SQL Query:""",
            input_variables=["question"]
            )

    def format_results(self, results: List[tuple]) -> str:
        if not results:
            return "No results found"
        
        # Convert all results to strings and format them
        formatted_results = []
        for row in results:
            formatted_row = [str(item) for item in row]
            formatted_results.append(", ".join(formatted_row))
        
        return "\n".join(formatted_results)

    def ask_question(self, question: str) -> Dict[str, Any]:
        try:
            # Generate SQL query using LLM
            sql_query = self.llm.predict(self.prompt.format(question=question))
            
            # Clean up the query (remove any markdown formatting if present)
            sql_query = sql_query.replace('```sql', '').replace('```', '').strip()
            
            # Execute the query
            results = self.db.run(sql_query)
            formatted_results = self.format_results(results)
            
            # Generate response using the result
            response_prompt = f"""Based on the following information, provide a clear and concise answer:

            Question: {question}
            SQL Query: {sql_query}
            Query Results: {formatted_results}

            Answer in a natural, helpful way:"""
            
            answer = self.llm.predict(response_prompt)
            
            return {
                "question": question,
                "sql_query": sql_query,
                "results": formatted_results,
                "answer": answer
            }
            
        except Exception as e:
            return {"error": f"Error processing question: {str(e)}"}

# FastAPI implementation
app = FastAPI()
qa_server = RedshiftQAServer()

class Question(BaseModel):
    text: str

@app.post("/ask")
async def ask_question(question: Question):
    try:
        answer = qa_server.ask_question(question.text)
        return {"response": answer}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)