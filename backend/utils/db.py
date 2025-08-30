import os
import logging
from supabase import create_client, Client
from typing import Dict, List, Any, Optional

# Configure logging
logger = logging.getLogger(__name__)

class DatabaseManager:
    """Database manager for Supabase operations"""
    
    _instance = None
    _client = None
    
    def __new__(cls):
        """Singleton pattern to ensure only one database connection"""
        if cls._instance is None:
            cls._instance = super(DatabaseManager, cls).__new__(cls)
            cls._instance._initialize_client()
        return cls._instance
    
    def _initialize_client(self) -> None:
        """Initialize the Supabase client
        Prefer the service role key when available to avoid RLS permission errors on the backend.
        """
        url = os.environ.get("SUPABASE_URL")
        # Server-side key: prefer service role key, fallback to legacy SUPABASE_KEY if present.
        # Do NOT use anon/publishable keys on the backend for security.
        key = (
            os.environ.get("SUPABASE_SERVICE_ROLE_KEY")
            or os.environ.get("SUPABASE_KEY")
        )
        
        if not url or not key:
            raise ValueError("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY (or SUPABASE_KEY) must be set on the backend")
        
        try:
            self._client = create_client(url, key)
            logger.info("Supabase client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Supabase client: {str(e)}")
            raise
    
    @property
    def client(self) -> Client:
        """Get the Supabase client instance"""
        if self._client is None:
            self._initialize_client()
        return self._client
    
    def query_table(self, table_name: str, query_params: Optional[Dict] = None) -> List[Dict]:
        """
        Query a table with optional parameters
        
        Args:
            table_name: Name of the table to query
            query_params: Optional query parameters
            
        Returns:
            List of records matching the query
        """
        try:
            query = self.client.table(table_name).select("*")
            
            if query_params:
                if 'filter' in query_params:
                    for filter_item in query_params['filter']:
                        column, operator, value = filter_item
                        query = query.filter(column, operator, value)
                
                if 'order' in query_params:
                    column, direction = query_params['order']
                    query = query.order(column, ascending=(direction.lower() == 'asc'))
                
                if 'limit' in query_params:
                    query = query.limit(query_params['limit'])
            
            response = query.execute()
            return response.data
        except Exception as e:
            logger.error(f"Error querying table {table_name}: {str(e)}")
            raise
    
    def insert_record(self, table_name: str, record_data: Dict) -> Dict:
        """
        Insert a record into a table
        
        Args:
            table_name: Name of the table
            record_data: Data to insert
            
        Returns:
            The inserted record
        """
        try:
            response = self.client.table(table_name).insert(record_data).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Error inserting into table {table_name}: {str(e)}")
            raise
    
    def update_record(self, table_name: str, record_id: str, record_data: Dict) -> Dict:
        """
        Update a record in a table
        
        Args:
            table_name: Name of the table
            record_id: ID of the record to update
            record_data: Data to update
            
        Returns:
            The updated record
        """
        try:
            response = self.client.table(table_name).update(record_data).eq("id", record_id).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Error updating record in table {table_name}: {str(e)}")
            raise
    
    def delete_record(self, table_name: str, record_id: str) -> Dict:
        """
        Delete a record from a table
        
        Args:
            table_name: Name of the table
            record_id: ID of the record to delete
            
        Returns:
            The deleted record
        """
        try:
            response = self.client.table(table_name).delete().eq("id", record_id).execute()
            return response.data[0] if response.data else {}
        except Exception as e:
            logger.error(f"Error deleting record from table {table_name}: {str(e)}")
            raise

def get_supabase_client() -> Client:
    """
    Get the Supabase client instance
    
    Returns:
        Client: Supabase client instance
    """
    return DatabaseManager().client

def get_db_manager() -> DatabaseManager:
    """
    Get the database manager instance
    
    Returns:
        DatabaseManager: Database manager instance
    """
    return DatabaseManager()