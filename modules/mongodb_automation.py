import os
from typing import Dict, Any, List, Optional
from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, OperationFailure
from datetime import datetime, timedelta
import json
from dotenv import load_dotenv
import pandas as pd
from tabulate import tabulate
from urllib.parse import quote_plus

load_dotenv()

class MongoDBAutomation:
    def __init__(self):
        """Initialize MongoDB connection using environment variables"""
        # Get MongoDB credentials
        username = quote_plus(os.getenv('MONGODB_USERNAME', 'roystr'))
        password = quote_plus(os.getenv('MONGODB_PASSWORD', 'Vapt@123'))
        
        # Construct connection string
        self.connection_string = f"mongodb+srv://{username}:{password}@cluster0.fgmexoj.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
        
        # Initialize MongoDB client
        self.client = MongoClient(self.connection_string)
        self.db = self.client[os.getenv('MONGODB_DB_NAME', 'autovapt')]
        self._verify_connection()

    def _verify_connection(self):
        """Verify MongoDB connection"""
        try:
            self.client.admin.command('ping')
            print("Successfully connected to MongoDB Atlas")
        except ConnectionFailure:
            raise ConnectionError("Failed to connect to MongoDB Atlas")

    def get_collections(self) -> List[str]:
        """Get list of all collections in the database"""
        return self.db.list_collection_names()

    def get_collection_stats(self, collection_name: str) -> Dict[str, Any]:
        """Get statistics for a specific collection"""
        try:
            return self.db.command('collstats', collection_name)
        except OperationFailure as e:
            print(f"Error getting collection stats: {str(e)}")
            return {}

    def find_documents(self, 
                      collection_name: str, 
                      query: Dict[str, Any] = None,
                      sort_by: str = None,
                      sort_order: str = 'asc',
                      limit: int = 10) -> List[Dict[str, Any]]:
        """Find documents in a collection with optional sorting and limiting"""
        try:
            collection = self.db[collection_name]
            cursor = collection.find(query or {})
            
            if sort_by:
                sort_direction = ASCENDING if sort_order.lower() == 'asc' else DESCENDING
                cursor = cursor.sort(sort_by, sort_direction)
            
            if limit:
                cursor = cursor.limit(limit)
            
            return list(cursor)
        except Exception as e:
            print(f"Error finding documents: {str(e)}")
            return []

    def insert_document(self, collection_name: str, document: Dict[str, Any]) -> bool:
        """Insert a single document into a collection"""
        try:
            result = self.db[collection_name].insert_one(document)
            return result.acknowledged
        except Exception as e:
            print(f"Error inserting document: {str(e)}")
            return False

    def update_document(self, 
                       collection_name: str, 
                       query: Dict[str, Any],
                       update: Dict[str, Any]) -> bool:
        """Update documents matching the query"""
        try:
            result = self.db[collection_name].update_many(query, {'$set': update})
            return result.modified_count > 0
        except Exception as e:
            print(f"Error updating documents: {str(e)}")
            return False

    def delete_document(self, collection_name: str, query: Dict[str, Any]) -> bool:
        """Delete documents matching the query"""
        try:
            result = self.db[collection_name].delete_many(query)
            return result.deleted_count > 0
        except Exception as e:
            print(f"Error deleting documents: {str(e)}")
            return False

    def export_collection(self, 
                         collection_name: str, 
                         output_format: str = 'json',
                         output_file: str = None) -> bool:
        """Export collection to file in specified format"""
        try:
            documents = list(self.db[collection_name].find())
            
            if not output_file:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                output_file = f"{collection_name}_{timestamp}.{output_format}"
            
            if output_format.lower() == 'json':
                with open(output_file, 'w') as f:
                    json.dump(documents, f, indent=2, default=str)
            elif output_format.lower() == 'csv':
                df = pd.DataFrame(documents)
                df.to_csv(output_file, index=False)
            else:
                raise ValueError(f"Unsupported output format: {output_format}")
            
            print(f"Successfully exported collection to {output_file}")
            return True
        except Exception as e:
            print(f"Error exporting collection: {str(e)}")
            return False

    def import_collection(self, 
                         collection_name: str, 
                         input_file: str,
                         input_format: str = 'json') -> bool:
        """Import data from file into collection"""
        try:
            if input_format.lower() == 'json':
                with open(input_file, 'r') as f:
                    documents = json.load(f)
            elif input_format.lower() == 'csv':
                df = pd.read_csv(input_file)
                documents = df.to_dict('records')
            else:
                raise ValueError(f"Unsupported input format: {input_format}")
            
            if documents:
                result = self.db[collection_name].insert_many(documents)
                return result.acknowledged
            return False
        except Exception as e:
            print(f"Error importing collection: {str(e)}")
            return False

    def create_index(self, 
                    collection_name: str, 
                    field: str,
                    unique: bool = False) -> bool:
        """Create an index on a field"""
        try:
            self.db[collection_name].create_index(field, unique=unique)
            return True
        except Exception as e:
            print(f"Error creating index: {str(e)}")
            return False

    def get_indexes(self, collection_name: str) -> List[Dict[str, Any]]:
        """Get all indexes for a collection"""
        try:
            return list(self.db[collection_name].list_indexes())
        except Exception as e:
            print(f"Error getting indexes: {str(e)}")
            return []

    def display_collection(self, 
                          collection_name: str,
                          query: Dict[str, Any] = None,
                          limit: int = 10) -> None:
        """Display collection contents in a formatted table"""
        try:
            documents = self.find_documents(collection_name, query, limit=limit)
            if documents:
                df = pd.DataFrame(documents)
                print(f"\nCollection: {collection_name}")
                print(tabulate(df, headers='keys', tablefmt='psql', showindex=False))
            else:
                print(f"No documents found in collection: {collection_name}")
        except Exception as e:
            print(f"Error displaying collection: {str(e)}")

    def backup_collection(self, collection_name: str) -> bool:
        """Create a backup of a collection"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_file = f"backup_{collection_name}_{timestamp}.json"
            return self.export_collection(collection_name, 'json', backup_file)
        except Exception as e:
            print(f"Error backing up collection: {str(e)}")
            return False

    def restore_collection(self, 
                          collection_name: str,
                          backup_file: str) -> bool:
        """Restore a collection from backup"""
        try:
            # Drop existing collection
            self.db[collection_name].drop()
            # Import from backup
            return self.import_collection(collection_name, backup_file, 'json')
        except Exception as e:
            print(f"Error restoring collection: {str(e)}")
            return False

    def close(self):
        """Close MongoDB connection"""
        if hasattr(self, 'client'):
            self.client.close()
            print("MongoDB connection closed") 