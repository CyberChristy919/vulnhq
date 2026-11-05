"""Adds new columns and tables to an existing VulnHQ database.

Safe to run more than once. Run after pulling changes that add fields:
    python -m scripts.migrate_db
"""

from sqlalchemy import text

from app.database import Base, engine

COLUMNS = [
    ("applications", "money_movement", "VARCHAR(30) NOT NULL DEFAULT 'none'"),
    ("assets", "external_id", "VARCHAR(100)"),
    ("assets", "asset_type", "VARCHAR(50)"),
    ("assets", "department", "VARCHAR(100)"),
    ("assets", "os", "VARCHAR(255)"),
    ("assets", "os_version", "VARCHAR(100)"),
    ("assets", "last_scan_date", "DATE"),
    ("assets", "money_movement", "VARCHAR(30) NOT NULL DEFAULT 'none'"),
    ("assets", "data_classification", "VARCHAR(50)"),
    ("findings", "software", "VARCHAR(255)"),
    ("findings", "confidence", "VARCHAR(20) NOT NULL DEFAULT 'confirmed'"),
    ("findings", "match_note", "TEXT"),
]


def main():
    # Creates any brand-new tables (e.g. installed_software)
    Base.metadata.create_all(bind=engine)
    with engine.begin() as conn:
        for table, column, definition in COLUMNS:
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {definition}"))
    print(f"Database up to date ({len(COLUMNS)} columns checked)")


if __name__ == "__main__":
    main()
