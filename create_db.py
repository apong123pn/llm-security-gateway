# create_db.py
import asyncio
import asyncpg

async def create_database():
    try:
        # Connect to PostgreSQL
        conn = await asyncpg.connect(
            user='postgres',
            password='SSnipey9863',
            database='postgres',
            host='localhost'
        )
        
        # Check if database exists
        result = await conn.fetchval("SELECT 1 FROM pg_database WHERE datname = 'llm_gateway'")
        
        if not result:
            # Create the database
            await conn.execute('CREATE DATABASE llm_gateway')
            print("=" * 50)
            print("✅ SUCCESS: Database 'llm_gateway' created!")
            print("=" * 50)
        else:
            print("=" * 50)
            print("✅ Database 'llm_gateway' already exists.")
            print("=" * 50)
        
        await conn.close()
        
    except Exception as e:
        print("=" * 50)
        print("❌ ERROR: Could not connect to PostgreSQL")
        print("=" * 50)
        print(f"Error details: {e}")
        print("\nTroubleshooting tips:")
        print("1. Make sure PostgreSQL is installed")
        print("2. Make sure PostgreSQL service is running")
        print("3. Check your password is correct: SSnipey9863")
        print("4. Try running PowerShell as Administrator")

if __name__ == "__main__":
    asyncio.run(create_database())