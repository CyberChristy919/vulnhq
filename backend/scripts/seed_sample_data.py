"""Creates sample applications, servers and findings so the Fix List has data.

Safe to run more than once: existing records are skipped, not duplicated.
Run after load_kev and load_epss:  python -m scripts.seed_sample_data
"""

from sqlalchemy import select

from app.database import Base, SessionLocal, engine
from app.models import Application, Asset, Finding, Vulnerability

APPLICATIONS = [
    # name, criticality, data classification, internet-facing, money movement
    ("Customer Portal", 5, "confidential", True, "outbound_payments"),
    ("Wire Transfer System", 5, "restricted", False, "outbound_payments"),
    ("General Ledger", 4, "confidential", False, "internal_transfers"),
    ("HR Intranet", 3, "confidential", False, "none"),
    ("Marketing Website", 2, "public", True, "none"),
]

# Two servers per application: (hostname, IP, application name)
ASSETS = [
    ("portal-web-01", "10.10.1.11", "Customer Portal"),
    ("portal-app-01", "10.10.1.21", "Customer Portal"),
    ("wire-app-01", "10.20.1.11", "Wire Transfer System"),
    ("wire-db-01", "10.20.1.31", "Wire Transfer System"),
    ("gl-app-01", "10.30.1.11", "General Ledger"),
    ("gl-db-01", "10.30.1.31", "General Ledger"),
    ("hr-web-01", "10.40.1.11", "HR Intranet"),
    ("hr-db-01", "10.40.1.31", "HR Intranet"),
    ("mkt-web-01", "10.50.1.11", "Marketing Website"),
    ("mkt-cms-01", "10.50.1.21", "Marketing Website"),
]

FINDINGS_PER_ASSET = 4


def main():
    Base.metadata.create_all(bind=engine)

    with SessionLocal() as db:
        # Applications
        apps = {}
        for name, crit, data_class, internet, money in APPLICATIONS:
            app_ = db.scalar(select(Application).where(Application.name == name))
            if app_ is None:
                app_ = Application(
                    name=name,
                    criticality=crit,
                    data_classification=data_class,
                    internet_facing=internet,
                    money_movement=money,
                    business_owner="Sample Owner",
                    technical_owner="Sample Team",
                )
                db.add(app_)
            apps[name] = app_
        db.flush()

        # Assets (inherit criticality and exposure from their application)
        assets = []
        for hostname, ip, app_name in ASSETS:
            asset = db.scalar(select(Asset).where(Asset.hostname == hostname))
            if asset is None:
                app_ = apps[app_name]
                asset = Asset(
                    hostname=hostname,
                    ip_address=ip,
                    owner=app_.technical_owner,
                    application_id=app_.id,
                    criticality=app_.criticality,
                    internet_facing=app_.internet_facing and "web" in hostname,
                )
                db.add(asset)
            assets.append(asset)
        db.flush()

        # Mix of high- and low-likelihood KEV CVEs so the ranking is interesting
        high = db.scalars(
            select(Vulnerability).order_by(Vulnerability.epss_score.desc().nulls_last()).limit(20)
        ).all()
        low = db.scalars(
            select(Vulnerability).order_by(Vulnerability.epss_score.asc().nulls_last()).limit(20)
        ).all()
        pool = [v for pair in zip(high, low) for v in pair]
        if not pool:
            print("No vulnerabilities found. Run load_kev and load_epss first.")
            return

        added = 0
        for i, asset in enumerate(assets):
            for j in range(FINDINGS_PER_ASSET):
                vuln = pool[(i * FINDINGS_PER_ASSET + j) % len(pool)]
                exists = db.scalar(
                    select(Finding).where(Finding.asset_id == asset.id, Finding.cve_id == vuln.cve_id)
                )
                if exists is None:
                    db.add(Finding(asset_id=asset.id, cve_id=vuln.cve_id, status="open"))
                    added += 1

        db.commit()

    print(f"Sample data ready: {len(apps)} applications, {len(assets)} assets, {added} new findings")


if __name__ == "__main__":
    main()
