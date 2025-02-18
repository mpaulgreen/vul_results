from pymongo import MongoClient
import json
from bson import json_util

client = MongoClient("mongodb://localhost:27017/")
db_name = 'agent-morpheus-client'
db = client[db_name]
collection = db['reports']


def parse_json(data):
    return json.loads(json_util.dumps(data))


def extract_justification(data):
    """
    Extracts 'justification.status' and 'justification.label' from a JSON object.

    Args:
        data (str or dict): A JSON string or dictionary.

    Returns:
        tuple: A tuple containing (status, label), or (None, None) if not found.
    """
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON string")

    if not isinstance(data, dict):
        return "NaN", "NaN"

    output = data.get("output", {})
    justification = output[0].get("justification",{})
    status = justification.get("status")
    label = justification.get("label")
    
    return status, label


def find_document_by_scan_id(collection, scan_id):
    """
    Searches for a single document in the MongoDB collection where 'scan.id' matches the given value.

    Args:
        collection: The MongoDB collection object.
        scan_id: The value to search for in 'scan.id'.

    Returns:
        dict or None: The document matching the criteria, or None if no document is found.
    """
    # Query to match the given 'scan.id'
    query = {
        "input.scan.id": scan_id
    }
    
    # Perform the query and return a single document
    return collection.find_one(query)