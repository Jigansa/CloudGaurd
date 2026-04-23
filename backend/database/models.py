from sqlalchemy import Column, Integer, Float, String
from backend.database.database import Base

class DriftLog(Base):
    __tablename__ = "drift_logs"

    id = Column(Integer, primary_key=True, index=True)
    day_label = Column(String, index=True)
    aws_score = Column(Float, default=0)
    azure_score = Column(Float, default=0)
    gcp_score = Column(Float, default=0)
    audit_snapshot = Column(String, nullable=True)
    has_drift = Column(Integer, default=0)  # Boolean equivalent for SQLite
