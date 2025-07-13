# Model Context Protocol (MCP) for Redshift Sales Analytics

This project implements a natural language interface for querying Redshift sales data using AWS Bedrock and LangChain. Users can ask questions in plain English and get SQL-powered responses about sales data.

## 🚀 Quick Start

```bash
# Clone repository
git clone https://github.com/vamsiarchitect/MCP4Redshift.git
cd MCP4Redshift

# Set up Python environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.template .env
# Edit .env with your Redshift credentials

# Start server
python3 server.py

# In another terminal
python3 client.py

**Architecture**
Server: Handles natural language processing and SQL generation using Bedrock
Client: Provides interactive interface for querying
Database: Amazon Redshift with sales data
Model: AWS Bedrock (Claude v2)
 **Data Schema**
CREATE TABLE sales (
    Date DATE,
    Product VARCHAR(50),
    Region VARCHAR(50),
    Quantity INTEGER,
    Unit_Price DECIMAL(10,2),
    Total_Amount DECIMAL(10,2)
);
** Prerequisites**
AWS Account with access to:
Amazon Redshift
AWS Bedrock
IAM permissions
Python 3.8+
Redshift cluster with sales data
**Sample Questions**
- "What was the total sales in 2022?"
- "Show me top 5 products by revenue"
- "Compare sales between regions"
- "What's the average order value?"
- "Show me monthly sales trends"
**Setup Details**
AWS Configuration
# Required IAM permissions
- redshift:*
- bedrock:InvokeModel
**Environment Variables**
REDSHIFT_HOST=your-cluster-endpoint
REDSHIFT_PASSWORD=your-cluster-password
**Dependencies**
langchain-community
langchain-aws
psycopg2-binary
python-dotenv
fastapi
uvicorn
requests
boto3
📚 Components
server.py: Main server implementing NLP and SQL generation
client.py: Interactive client interface
test_qa.py: Test cases and examples
🔍 Usage Examples
# Start the server
python3 server.py

# In another terminal, start the client
python3 client.py

# Example interaction:
> What was the total revenue last year?
SQL: SELECT SUM(Total_Amount) FROM sales WHERE EXTRACT(YEAR FROM Date) = 2022
Result: \$1,234,567

> Which product has highest sales?
SQL: SELECT Product, SUM(Total_Amount) as Revenue 
     FROM sales 
     GROUP BY Product 
     ORDER BY Revenue DESC 
     LIMIT 1
Result: Laptop: \$789,012
**Security Notes**
Keep your .env file secure
Use appropriate IAM roles
Don't commit sensitive credentials
Use security groups to restrict access
🔄 Development Workflow
Start the server
Run the client
Ask questions in natural language
Get SQL queries and results
Use test cases for validation
**Troubleshooting**
Common issues and solutions:

Connection errors: Check security groups
Authentication issues: Verify IAM roles
Query errors: Validate data types
📈 Performance
Average response time: ~2-3 seconds
Supports concurrent queries
Handles complex analytical questions
🤝 Contributing
Fork the repository
Create feature branch
Commit changes
Push to branch
Create Pull Request
📝 License
MIT License

👥 Contact
Create Issues for bugs
Pull Requests welcome
Questions: [GitHub Issues]
🙏 Acknowledgments
AWS Bedrock team
LangChain community
Contributors
🚦 Status
Project is: in progress

🗺️ Roadmap
 Add visualization support
 Implement caching
 Add more analytical capabilities
 Improve error handling
 Add batch processing

Optional Sections you might want to add:

1. **Deployment Guide**
```markdown
## 🚀 Deployment

Detailed steps for production deployment:
1. Set up AWS infrastructure
2. Configure security
3. Deploy application
4. Monitor performance
Best Practices
## 💡 Best Practices

- Use connection pooling
- Implement query timeouts
- Cache frequent queries
- Monitor resource usage
Configuration Options
## ⚙️ Configuration

Detailed configuration options:
- Server settings
- Client parameters
- Model configurations
- Database options
