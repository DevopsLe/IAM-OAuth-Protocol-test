"""
Simple script to initialize the database.
"""

from app import app, db

with app.app_context():
    db.create_all()
    print("✓ Database initialized successfully!")
    print("  Tables created:")
    print("    - test_configurations")
    print("    - test_results")
    print("    - log_entries")
    print("    - saved_tokens")
