import os

# Simple database dependency function that returns None if database not available
def get_db():
    """Database dependency - returns None if database not available"""
    return None

# Initialize database function - does nothing if database not available
def init_db():
    """Initialize database - prints message and returns if database not available"""
    print("Database initialization skipped - using fallback mode")
    return

# Placeholder models for compatibility
class TenantModel:
    pass

class UserModel:
    pass

class SourceModel:
    pass

class NotificationModel:
    pass

class ReportModel:
    pass
