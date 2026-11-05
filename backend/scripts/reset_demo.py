"""Deletes all applications, assets, software and findings so a demo can start clean.

CVE data (KEV and EPSS) is kept, so you don't need to reload it.
Usage (from the backend folder):
    python -m scripts.reset_demo
"""

from sqlalchemy import delete

from app.database import SessionLocal
from app.models import Application, Asset, Finding, InstalledSoftware


def main():
    answer = input("This deletes all applications, assets and findings. Type RESET to continue: ")
    if answer.strip() != "RESET":
        print("Cancelled. Nothing was deleted.")
        return

    with SessionLocal() as db:
        counts = {}
        for model in (Finding, InstalledSoftware, Asset, Application):
            counts[model.__tablename__] = db.execute(delete(model)).rowcount
        db.commit()

    print("Deleted: " + ", ".join(f"{n} {t}" for t, n in counts.items()))
    print("KEV and EPSS data kept.")


if __name__ == "__main__":
    main()
