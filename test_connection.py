import psycopg2
from dotenv import load_dotenv
import os

load_dotenv()

def test_connection():
    try:
        # Print connection details for verification
        print(f"Attempting to connect to:")
        print(f"Host: {os.getenv('REDSHIFT_HOST')}")
        print(f"Database: sales_db")
        print(f"Port: 5439")
        
        conn = psycopg2.connect(
            dbname='dev',  # Change this to 'dev' as it's the default database
            host=os.getenv('REDSHIFT_HOST'),
            user='admin',
            password=os.getenv('REDSHIFT_PASSWORD'),
            port=5439
        )
        
        print("\nConnection successful!")
        
        # Test query
        cur = conn.cursor()
        cur.execute("SELECT current_database()")
        db_name = cur.fetchone()[0]
        print(f"Connected to database: {db_name}")
        
        cur.close()
        conn.close()
        
    except Exception as e:
        print(f"\nConnection error: {str(e)}")
        
if __name__ == "__main__":
    test_connection()