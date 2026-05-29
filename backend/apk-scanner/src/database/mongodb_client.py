"""
MongoDB Client for APK-Scanner
Handles all database operations with MongoDB
"""

import os
import logging
from datetime import datetime
from typing import Optional, Dict, List, Any
from pymongo import MongoClient, DESCENDING
from pymongo.errors import ConnectionFailure, OperationFailure
from bson import ObjectId

logger = logging.getLogger(__name__)


class MongoDBClient:
    """MongoDB client singleton for APK-Scanner"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self.uri = os.getenv('MONGODB_URI', 'mongodb://admin:securityplatform2024@localhost:27017/security_platform?authSource=admin')
        self.db_name = os.getenv('MONGODB_DATABASE', 'security_platform')
        self.input_collection = os.getenv('INPUT_COLLECTION', 'scans')
        self.output_collection = os.getenv('OUTPUT_COLLECTION', 'apk_results')
        
        self.client: Optional[MongoClient] = None
        self.db = None
        self._initialized = True
        
    def connect(self) -> bool:
        """Connect to MongoDB"""
        try:
            self.client = MongoClient(self.uri, serverSelectionTimeoutMS=5000)
            # Test connection
            self.client.admin.command('ping')
            self.db = self.client[self.db_name]
            logger.info(f"✅ Connected to MongoDB: {self.db_name}")
            return True
        except ConnectionFailure as e:
            logger.error(f"❌ Failed to connect to MongoDB: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from MongoDB"""
        if self.client:
            self.client.close()
            logger.info("Disconnected from MongoDB")
    
    def is_connected(self) -> bool:
        """Check if connected to MongoDB"""
        try:
            if self.client:
                self.client.admin.command('ping')
                return True
        except Exception:
            pass
        return False
    
    # ==================== SCANS Collection ====================
    
    def get_scan_input(self, scan_id: str) -> Optional[Dict]:
        """Get scan input data from 'scans' collection"""
        try:
            return self.db[self.input_collection].find_one({"scan_id": scan_id})
        except Exception as e:
            logger.error(f"Error getting scan input: {e}")
            return None
    
    def create_scan(self, scan_data: Dict) -> str:
        """Create a new scan entry"""
        try:
            scan_data['created_at'] = datetime.utcnow()
            scan_data['updated_at'] = datetime.utcnow()
            result = self.db[self.input_collection].insert_one(scan_data)
            logger.info(f"Created scan: {scan_data.get('scan_id')}")
            return str(result.inserted_id)
        except Exception as e:
            logger.error(f"Error creating scan: {e}")
            raise
    
    def update_scan_status(self, scan_id: str, stage: str, status: str):
        """Update scan stage status"""
        try:
            self.db[self.input_collection].update_one(
                {"scan_id": scan_id},
                {
                    "$set": {
                        f"stages.{stage}": status,
                        "updated_at": datetime.utcnow()
                    }
                }
            )
            logger.info(f"Updated scan {scan_id} stage {stage} to {status}")
        except Exception as e:
            logger.error(f"Error updating scan status: {e}")
    
    # ==================== APK_RESULTS Collection ====================
    
    def save_apk_results(self, scan_id: str, results: Dict) -> str:
        """Save APK analysis results to 'apk_results' collection"""
        try:
            document = {
                "scan_id": scan_id,
                "status": results.get("status", "completed"),
                "created_at": datetime.utcnow(),
                "updated_at": datetime.utcnow(),
                "results": results
            }
            
            result = self.db[self.output_collection].update_one(
                {"scan_id": scan_id},
                {"$set": document},
                upsert=True
            )
            
            logger.info(f"✅ APK results saved for scan_id: {scan_id}")
            return scan_id
        except Exception as e:
            logger.error(f"Error saving APK results: {e}")
            raise
    
    def get_apk_results(self, scan_id: str) -> Optional[Dict]:
        """Get APK results by scan_id"""
        try:
            return self.db[self.output_collection].find_one({"scan_id": scan_id})
        except Exception as e:
            logger.error(f"Error getting APK results: {e}")
            return None
    
    def get_apk_results_by_hash(self, file_hash: str) -> Optional[Dict]:
        """Get APK results by file hash"""
        try:
            return self.db[self.output_collection].find_one({"results.file_hash": file_hash})
        except Exception as e:
            logger.error(f"Error getting APK results by hash: {e}")
            return None
    
    def get_all_apk_results(self, limit: int = 100) -> List[Dict]:
        """Get all APK results"""
        try:
            cursor = self.db[self.output_collection].find().sort("created_at", DESCENDING).limit(limit)
            return list(cursor)
        except Exception as e:
            logger.error(f"Error getting all APK results: {e}")
            return []
    
    def delete_apk_results(self, scan_id: str) -> bool:
        """Delete APK results by scan_id"""
        try:
            result = self.db[self.output_collection].delete_one({"scan_id": scan_id})
            return result.deleted_count > 0
        except Exception as e:
            logger.error(f"Error deleting APK results: {e}")
            return False
    
    def get_statistics(self) -> Dict:
        """Get scanning statistics"""
        try:
            total_scans = self.db[self.output_collection].count_documents({})
            completed = self.db[self.output_collection].count_documents({"status": "completed"})
            failed = self.db[self.output_collection].count_documents({"status": "failed"})
            
            # Average security score
            pipeline = [
                {"$match": {"status": "completed"}},
                {"$group": {
                    "_id": None,
                    "avg_score": {"$avg": "$results.security_score.score"}
                }}
            ]
            avg_result = list(self.db[self.output_collection].aggregate(pipeline))
            avg_score = avg_result[0]['avg_score'] if avg_result else 0
            
            return {
                "total_scans": total_scans,
                "completed": completed,
                "failed": failed,
                "average_security_score": round(avg_score, 2) if avg_score else 0
            }
        except Exception as e:
            logger.error(f"Error getting statistics: {e}")
            return {}


# Singleton instance
mongodb_client = MongoDBClient()
