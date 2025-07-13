
```markdown
# Model Context Protocol (MCP) for Redshift Sales Analytics

Natural language interface for querying Redshift sales data using AWS Bedrock and LangChain. Ask questions in plain English and get SQL-powered responses about your sales data.

## Quick Start

```bash
# Clone repository
git clone https://github.com/vamsiarchitect/MCP4Redshift.git
cd MCP4Redshift

# Set up Python environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install langchain-community langchain-aws boto3 fastapi uvicorn requests python-dotenv

# Configure environment
cp .env.template .env
# Edit .env with your Redshift credentials

# Start server
python3 server.py

# In another terminal
python3 client.py
```

## Architecture
- **Server**: FastAPI server with Bedrock and LangChain integration
- **LLM**: AWS Bedrock (Claude v2) for natural language understanding
- **Database**: Amazon Redshift accessed through LangChain utilities
- **Client**: Interactive Python client for querying

## Data Schema

```sql
CREATE TABLE sales (
    Date DATE,
    Product VARCHAR(50),
    Region VARCHAR(50),
    Quantity INTEGER,
    Unit_Price DECIMAL(10,2),
    Total_Amount DECIMAL(10,2)
);
```

## Prerequisites

- AWS Account with access to:
  - Amazon Redshift
  - AWS Bedrock
  - IAM permissions
- Python 3.8+
- Redshift cluster with sales data

## Sample Questions

- "What was the total sales in 2022?"
- "Show me top 5 products by revenue"
- "Compare sales between regions"
- "What's the average order value?"
- "Show me monthly sales trends"

## Setup Details

### AWS Configuration
Required IAM permissions:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "redshift-data:ExecuteStatement",
                "bedrock:InvokeModel"
            ],
            "Resource": "*"
        }
    ]
}
```

### Environment Variables
```bash
REDSHIFT_HOST=your-cluster-endpoint
REDSHIFT_PASSWORD=your-redshift-password
```

### Key Dependencies
```bash
langchain-community  # For database utilities
langchain-aws       # For Bedrock integration
boto3               # AWS SDK
fastapi             # API server
uvicorn            # ASGI server
requests           # HTTP client
python-dotenv      # Environment management
```

## Components

- `server.py`: FastAPI server with Bedrock and LangChain integration
- `client.py`: Interactive command-line interface
- `test_qa.py`: Test cases and examples

## Usage Examples

```python
# Start the server
python3 server.py

# In another terminal, start the client
python3 client.py

# Example interaction:
> What was the total revenue last year?
SQL: SELECT SUM(Total_Amount) FROM sales WHERE EXTRACT(YEAR FROM Date) = 2022
Result: $1,234,567

> Which product has highest sales?
SQL: SELECT Product, SUM(Total_Amount) as Revenue 
     FROM sales 
     GROUP BY Product 
     ORDER BY Revenue DESC 
     LIMIT 1
Result: Laptop: $789,012
```

## Security Notes

- Store credentials in .env file (not in code)
- Use appropriate IAM roles with least privilege
- Secure your Redshift cluster access
- Use AWS security best practices

## Troubleshooting

Common issues and solutions:
- Bedrock access issues: Check IAM permissions
- Connection errors: Verify Redshift endpoint
- Query errors: Check SQL syntax
- Authentication: Verify credentials in .env

## Development Workflow

1. Start the FastAPI server
2. Run the interactive client
3. Ask questions in natural language
4. Review generated SQL and results
5. Use test cases for validation

## Contributing

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## License

MIT License

## Contact

- Create Issues for bugs
- Pull Requests welcome
- Questions: [GitHub Issues]

## Roadmap

- [ ] Add visualization capabilities
- [ ] Implement query caching
- [ ] Add more analytical features
- [ ] Enhance error handling
- [ ] Support batch processing
- [ ] Add more LLM models

## Status

Project is: _in progress_
```

This README now accurately reflects:
1. The actual dependencies we used
2. The correct architecture with LangChain and Bedrock
3. The proper IAM permissions needed
4. No mention of psycopg2 or direct database drivers
5. Accurate troubleshooting steps

Would you like me to:
1. Add any specific sections?
2. Include more technical details?
3. Add example responses?
4. Make any other adjustments?
