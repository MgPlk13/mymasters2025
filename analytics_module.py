from sqlalchemy import create_engine, Column, Integer, String, Float, Text, ForeignKey
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from config_db import DATABASE_URI
from datetime import datetime

Base = declarative_base()
engine = create_engine(DATABASE_URI)
Session = sessionmaker(bind=engine)

class AttackLog(Base):
    __tablename__ = 'attack_logs'
    id = Column(Integer, primary_key=True)
    timestamp = Column(String, nullable=False)
    reason = Column(Text, nullable=False)
    query = Column(Text, nullable=False)
    score = Column(Float)
    source_ip = Column(String, default='127.0.0.1')
    status = Column(String, default='blocked')
    attack_type_id = Column(Integer, ForeignKey("attack_types.id"))
    attack_type = relationship("AttackType")

class AttackType(Base):
    __tablename__ = 'attack_types'
    id = Column(Integer, primary_key=True)
    code = Column(String, unique=True, nullable=False)
    description = Column(Text)

class User(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    role = Column(String, default='user', nullable=False)
    activities = relationship("UserActivity", back_populates="user")

class UserActivity(Base):
    __tablename__ = 'user_activity'
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    action = Column(String)
    timestamp = Column(String)
    user = relationship("User", back_populates="activities")

def log_blocked_query(reason: str, sql: str, score=None, source_ip="127.0.0.1"):
    with Session() as db:
        attack = AttackLog(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            reason=reason,
            query=sql.strip(),
            score=score,
            source_ip=source_ip,
            status="blocked"
        )
        db.add(attack)
        db.commit()
        print(f"✅ Запис атаки: {reason} | {sql.strip()}")

if __name__ == "__main__":
    Base.metadata.create_all(engine)
    print("✅ ORM-таблиці створено")
