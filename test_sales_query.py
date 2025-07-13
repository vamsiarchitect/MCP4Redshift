import psycopg2
from dotenv import load_dotenv
import os

load_dotenv()

def test_sales_queries():
    try:
        # Connect to Redshift
        conn = psycopg2.connect(
            host=os.getenv('REDSHIFT_HOST'),
            dbname='sales_db',
            user='admin',
            password=os.getenv('REDSHIFT_PASSWORD'),
            port=5439
        )
        
        cur = conn.cursor()
        
        # Test queries
        queries = [
            ("Count total records", "SELECT COUNT(*) FROM sales"),
            ("Sample data", "SELECT * FROM sales LIMIT 5"),
            ("Total sales by product", "SELECT Product, SUM(Total_Amount) as Total_Sales FROM sales GROUP BY Product ORDER BY Total_Sales DESC"),
            ("Sales by region", "SELECT Region, COUNT(*) as Transaction_Count, SUM(Total_Amount) as Total_Sales FROM sales GROUP BY Region ORDER BY Total_Sales DESC")
        ]
        
        # Execute each query
        for description, query in queries:
            print(f"\n{description}:")
            try:
                cur.execute(query)
                results = cur.fetchall()
                for row in results:
                    print(row)
            except Exception as e:
                print(f"Error executing query: {str(e)}")
        
        cur.close()
        conn.close()
        
    except Exception as e:
        print(f"Connection error: {str(e)}")

if __name__ == "__main__":
    test_sales_queries()