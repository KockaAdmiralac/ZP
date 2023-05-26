from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

databaseUrl = 'sqlite:///keyring.db'
engine = create_engine(databaseUrl)
Session = sessionmaker(bind=engine)
Base = declarative_base()

def databaseStartUp():
    Base.metadata.create_all(bind=engine)
