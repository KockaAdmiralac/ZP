from typing import List
from sqlalchemy import TIMESTAMP, Column, String, func
from lib import Key
from lib.pem import import_key_from_bytes
from lib.keyring import Session, Base

session = Session()

class PrivateKeyRing(Base):
    __tablename__ = 'private_key_ring'

    key_id = Column(String, primary_key=True)
    timestamp = Column(TIMESTAMP, nullable=False, default=func.now())
    name = Column(String, nullable=False)
    public_key = Column(String, nullable=False)
    private_key = Column(String, nullable=False)
    user_id = Column(String, nullable=False)

    def __init__(self, key_id, name, public_key, private_key, user_id, timestamp=None, **kwargs):
        self.key_id = key_id
        self.timestamp = timestamp
        self.name = name
        self.public_key = public_key
        self.private_key = private_key
        self.user_id = user_id
        super().__init__(**kwargs)

    def get_public_key_obj(self) -> Key:
        return import_key_from_bytes(self.public_key.encode('utf-8'))

    def get_private_key_obj(self, passphrase: str) -> Key:
        return import_key_from_bytes(self.private_key.encode('utf-8'), passphrase)

    @classmethod
    def insert(cls, model: 'PrivateKeyRing'):
        try:
            session.add(model)
            session.commit()
            return model
        except Exception as e:
            session.rollback()
            raise e
    
    @classmethod
    def delete_by_key_id(cls, key_id):
        try:
            instance = session.query(cls).filter_by(key_id=key_id).first()
            if instance:
                session.delete(instance)
                session.commit()
        except Exception as e:
            session.rollback()
            raise e
    
    @classmethod
    def get_all(cls) -> List['PrivateKeyRing']:
        return session.query(cls).all()
    
    @classmethod
    def get_by_key_id(cls, key_id) -> 'PrivateKeyRing':
        instance = session.query(cls).filter_by(key_id=key_id).first()
        return instance

class PublicKeyRing(Base):
    __tablename__ = 'public_key_ring'

    key_id = Column(String, primary_key=True)
    timestamp = Column(TIMESTAMP, nullable=False, default=func.now())
    public_key = Column(String, nullable=False)
    user_id = Column(String, nullable=False)
    signature = Column(String, nullable=True)
