import psycopg2
from psycopg2.extras import Json
from datetime import datetime
import json
from typing import Dict, Any, List, Optional
import os
from dotenv import load_dotenv

load_dotenv()

class Database:
    def __init__(self):
        self.conn = None
        self.connect()
        self.create_tables()

    def connect(self):
        """Connect to PostgreSQL database"""
        try:
            self.conn = psycopg2.connect(
                dbname=os.getenv('DB_NAME', 'autovapt'),
                user=os.getenv('DB_USER', 'postgres'),
                password=os.getenv('DB_PASSWORD', ''),
                host=os.getenv('DB_HOST', 'localhost'),
                port=os.getenv('DB_PORT', '5432')
            )
            print("Connected to PostgreSQL database")
        except Exception as e:
            print(f"Error connecting to database: {str(e)}")
            raise

    def create_tables(self):
        """Create necessary tables if they don't exist"""
        try:
            with self.conn.cursor() as cur:
                # Create targets table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS targets (
                        id SERIAL PRIMARY KEY,
                        domain VARCHAR(255) NOT NULL,
                        ip_address VARCHAR(45),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                # Create scans table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS scans (
                        id SERIAL PRIMARY KEY,
                        target_id INTEGER REFERENCES targets(id),
                        scan_type VARCHAR(50) NOT NULL,
                        status VARCHAR(20) NOT NULL,
                        start_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        end_time TIMESTAMP,
                        results JSONB,
                        error_message TEXT
                    )
                """)

                # Create vulnerabilities table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS vulnerabilities (
                        id SERIAL PRIMARY KEY,
                        scan_id INTEGER REFERENCES scans(id),
                        vulnerability_type VARCHAR(50) NOT NULL,
                        severity VARCHAR(20) NOT NULL,
                        description TEXT,
                        location TEXT,
                        evidence TEXT,
                        remediation TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                # Create configurations table
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS configurations (
                        id SERIAL PRIMARY KEY,
                        module_name VARCHAR(50) NOT NULL,
                        config_data JSONB NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

                self.conn.commit()
                print("Database tables created successfully")
        except Exception as e:
            print(f"Error creating tables: {str(e)}")
            raise

    def add_target(self, domain: str, ip_address: Optional[str] = None) -> int:
        """Add a new target to the database"""
        try:
            with self.conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO targets (domain, ip_address)
                    VALUES (%s, %s)
                    RETURNING id
                """, (domain, ip_address))
                target_id = cur.fetchone()[0]
                self.conn.commit()
                return target_id
        except Exception as e:
            print(f"Error adding target: {str(e)}")
            raise

    def add_scan(self, target_id: int, scan_type: str, status: str = 'running') -> int:
        """Add a new scan to the database"""
        try:
            with self.conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO scans (target_id, scan_type, status)
                    VALUES (%s, %s, %s)
                    RETURNING id
                """, (target_id, scan_type, status))
                scan_id = cur.fetchone()[0]
                self.conn.commit()
                return scan_id
        except Exception as e:
            print(f"Error adding scan: {str(e)}")
            raise

    def update_scan_results(self, scan_id: int, results: Dict[str, Any], status: str = 'completed'):
        """Update scan results and status"""
        try:
            with self.conn.cursor() as cur:
                cur.execute("""
                    UPDATE scans
                    SET results = %s, status = %s, end_time = CURRENT_TIMESTAMP
                    WHERE id = %s
                """, (Json(results), status, scan_id))
                self.conn.commit()
        except Exception as e:
            print(f"Error updating scan results: {str(e)}")
            raise

    def add_vulnerability(self, scan_id: int, vulnerability_type: str, severity: str,
                         description: str, location: str, evidence: str, remediation: str):
        """Add a vulnerability to the database"""
        try:
            with self.conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO vulnerabilities 
                    (scan_id, vulnerability_type, severity, description, location, evidence, remediation)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (scan_id, vulnerability_type, severity, description, location, evidence, remediation))
                self.conn.commit()
        except Exception as e:
            print(f"Error adding vulnerability: {str(e)}")
            raise

    def get_scan_history(self, target_id: int) -> List[Dict[str, Any]]:
        """Get scan history for a target"""
        try:
            with self.conn.cursor() as cur:
                cur.execute("""
                    SELECT s.*, t.domain
                    FROM scans s
                    JOIN targets t ON s.target_id = t.id
                    WHERE s.target_id = %s
                    ORDER BY s.start_time DESC
                """, (target_id,))
                columns = [desc[0] for desc in cur.description]
                return [dict(zip(columns, row)) for row in cur.fetchall()]
        except Exception as e:
            print(f"Error getting scan history: {str(e)}")
            raise

    def get_vulnerabilities(self, scan_id: int) -> List[Dict[str, Any]]:
        """Get vulnerabilities for a scan"""
        try:
            with self.conn.cursor() as cur:
                cur.execute("""
                    SELECT *
                    FROM vulnerabilities
                    WHERE scan_id = %s
                    ORDER BY severity DESC, created_at DESC
                """, (scan_id,))
                columns = [desc[0] for desc in cur.description]
                return [dict(zip(columns, row)) for row in cur.fetchall()]
        except Exception as e:
            print(f"Error getting vulnerabilities: {str(e)}")
            raise

    def save_configuration(self, module_name: str, config_data: Dict[str, Any]):
        """Save module configuration"""
        try:
            with self.conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO configurations (module_name, config_data)
                    VALUES (%s, %s)
                    ON CONFLICT (module_name) 
                    DO UPDATE SET config_data = %s, updated_at = CURRENT_TIMESTAMP
                """, (module_name, Json(config_data), Json(config_data)))
                self.conn.commit()
        except Exception as e:
            print(f"Error saving configuration: {str(e)}")
            raise

    def get_configuration(self, module_name: str) -> Optional[Dict[str, Any]]:
        """Get module configuration"""
        try:
            with self.conn.cursor() as cur:
                cur.execute("""
                    SELECT config_data
                    FROM configurations
                    WHERE module_name = %s
                """, (module_name,))
                result = cur.fetchone()
                return result[0] if result else None
        except Exception as e:
            print(f"Error getting configuration: {str(e)}")
            raise

    def close(self):
        """Close database connection"""
        if self.conn:
            self.conn.close()
            print("Database connection closed") 