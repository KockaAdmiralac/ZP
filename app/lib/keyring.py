from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

database_url = 'sqlite:///keyring.db'
engine = create_engine(database_url)
Session = sessionmaker(bind=engine)
Base = declarative_base()

def database_start_up():
    Base.metadata.create_all(bind=engine)
