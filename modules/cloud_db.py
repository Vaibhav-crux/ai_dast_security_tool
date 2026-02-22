import os
from typing import Dict, Any, Optional
import boto3
from pymongo import MongoClient
from dotenv import load_dotenv
import json
from datetime import datetime, timedelta

load_dotenv()

class CloudDatabase:
    def __init__(self, provider: str = 'aws'):
        self.provider = provider.lower()
        self.connection = None
        self.setup_connection()

    def setup_connection(self):
        """Setup connection to cloud database based on provider"""
        if self.provider == 'aws':
            self.setup_aws_rds()
        elif self.provider == 'mongodb':
            self.setup_mongodb()
        else:
            raise ValueError(f"Unsupported cloud provider: {self.provider}")

    def setup_aws_rds(self):
        """Setup connection to AWS RDS"""
        try:
            # Initialize RDS client
            self.rds_client = boto3.client(
                'rds',
                aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
                aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
                region_name=os.getenv('AWS_REGION', 'us-east-1')
            )

            # Get RDS endpoint
            self.endpoint = os.getenv('RDS_ENDPOINT')
            if not self.endpoint:
                # If endpoint not provided, get it from RDS instance
                response = self.rds_client.describe_db_instances(
                    DBInstanceIdentifier=os.getenv('RDS_INSTANCE_ID')
                )
                self.endpoint = response['DBInstances'][0]['Endpoint']['Address']

            print(f"Connected to AWS RDS at {self.endpoint}")
        except Exception as e:
            print(f"Error connecting to AWS RDS: {str(e)}")
            raise

    def setup_mongodb(self):
        """Setup connection to MongoDB Atlas"""
        try:
            # Get MongoDB connection string
            connection_string = os.getenv('MONGODB_URI')
            if not connection_string:
                raise ValueError("MongoDB connection string not provided")

            # Initialize MongoDB client
            self.mongo_client = MongoClient(connection_string)
            self.db = self.mongo_client[os.getenv('MONGODB_DB_NAME', 'autovapt')]
            print("Connected to MongoDB Atlas")
        except Exception as e:
            print(f"Error connecting to MongoDB Atlas: {str(e)}")
            raise

    def backup_database(self, backup_name: Optional[str] = None) -> Dict[str, Any]:
        """Create database backup"""
        if self.provider == 'aws':
            return self.backup_aws_rds(backup_name)
        elif self.provider == 'mongodb':
            return self.backup_mongodb(backup_name)

    def backup_aws_rds(self, backup_name: Optional[str] = None) -> Dict[str, Any]:
        """Create AWS RDS backup"""
        try:
            if not backup_name:
                backup_name = f"autovapt-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

            response = self.rds_client.create_db_snapshot(
                DBSnapshotIdentifier=backup_name,
                DBInstanceIdentifier=os.getenv('RDS_INSTANCE_ID')
            )

            return {
                "status": "success",
                "backup_id": response['DBSnapshot']['DBSnapshotIdentifier'],
                "message": "Backup created successfully"
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }

    def backup_mongodb(self, backup_name: Optional[str] = None) -> Dict[str, Any]:
        """Create MongoDB backup"""
        try:
            if not backup_name:
                backup_name = f"autovapt-backup-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

            # Create backup directory
            backup_dir = os.path.join('backups', backup_name)
            os.makedirs(backup_dir, exist_ok=True)

            # Export collections
            for collection in self.db.list_collection_names():
                output_file = os.path.join(backup_dir, f"{collection}.json")
                with open(output_file, 'w') as f:
                    for doc in self.db[collection].find():
                        f.write(json.dumps(doc) + '\n')

            return {
                "status": "success",
                "backup_path": backup_dir,
                "message": "Backup created successfully"
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }

    def restore_database(self, backup_id: str) -> Dict[str, Any]:
        """Restore database from backup"""
        if self.provider == 'aws':
            return self.restore_aws_rds(backup_id)
        elif self.provider == 'mongodb':
            return self.restore_mongodb(backup_id)

    def restore_aws_rds(self, backup_id: str) -> Dict[str, Any]:
        """Restore AWS RDS from snapshot"""
        try:
            response = self.rds_client.restore_db_instance_from_db_snapshot(
                DBInstanceIdentifier=os.getenv('RDS_INSTANCE_ID'),
                DBSnapshotIdentifier=backup_id
            )

            return {
                "status": "success",
                "message": "Restore initiated successfully"
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }

    def restore_mongodb(self, backup_path: str) -> Dict[str, Any]:
        """Restore MongoDB from backup"""
        try:
            # Clear existing collections
            for collection in self.db.list_collection_names():
                self.db[collection].delete_many({})

            # Import collections
            for file_name in os.listdir(backup_path):
                if file_name.endswith('.json'):
                    collection_name = file_name[:-5]
                    with open(os.path.join(backup_path, file_name), 'r') as f:
                        for line in f:
                            doc = json.loads(line)
                            self.db[collection_name].insert_one(doc)

            return {
                "status": "success",
                "message": "Restore completed successfully"
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }

    def get_database_metrics(self) -> Dict[str, Any]:
        """Get database performance metrics"""
        if self.provider == 'aws':
            return self.get_aws_rds_metrics()
        elif self.provider == 'mongodb':
            return self.get_mongodb_metrics()

    def get_aws_rds_metrics(self) -> Dict[str, Any]:
        """Get AWS RDS metrics"""
        try:
            cloudwatch = boto3.client('cloudwatch')
            metrics = {}

            # Get CPU utilization
            cpu_response = cloudwatch.get_metric_statistics(
                Namespace='AWS/RDS',
                MetricName='CPUUtilization',
                Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': os.getenv('RDS_INSTANCE_ID')}],
                StartTime=datetime.utcnow() - timedelta(hours=1),
                EndTime=datetime.utcnow(),
                Period=300,
                Statistics=['Average']
            )
            metrics['cpu_utilization'] = cpu_response['Datapoints']

            # Get free storage space
            storage_response = cloudwatch.get_metric_statistics(
                Namespace='AWS/RDS',
                MetricName='FreeStorageSpace',
                Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': os.getenv('RDS_INSTANCE_ID')}],
                StartTime=datetime.utcnow() - timedelta(hours=1),
                EndTime=datetime.utcnow(),
                Period=300,
                Statistics=['Average']
            )
            metrics['free_storage'] = storage_response['Datapoints']

            return {
                "status": "success",
                "metrics": metrics
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }

    def get_mongodb_metrics(self) -> Dict[str, Any]:
        """Get MongoDB metrics"""
        try:
            metrics = {}

            # Get database stats
            db_stats = self.db.command('dbStats')
            metrics['db_stats'] = db_stats

            # Get server status
            server_status = self.db.command('serverStatus')
            metrics['server_status'] = server_status

            return {
                "status": "success",
                "metrics": metrics
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }

    def close(self):
        """Close database connection"""
        if self.provider == 'mongodb' and hasattr(self, 'mongo_client'):
            self.mongo_client.close()
            print("MongoDB connection closed") 