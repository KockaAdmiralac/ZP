from typing import List
from sqlalchemy import TIMESTAMP, Column, Integer, String, func
from lib import Key
from lib.keyring import Session, Base

session = Session()

class PrivateKeyRing(Base):
    __tablename__ = 'PrivateKeyRing'

    keyID = Column(String, primary_key=True)
    timestamp = Column(TIMESTAMP, nullable=False, default=func.now())
    name = Column(String, nullable=False)
    publicKey = Column(String, nullable=False)
    enPrivateKey = Column(String, nullable=False)
    userID = Column(String, nullable=False)

    def __init__(self, keyObj: Key = None, keyID=None, timestamp=None, name=None, publicKey=None, enPrivateKey=None, userID=None, **kwargs):
        self._keyObj = keyObj
        self.keyID = keyID
        self.timestamp = timestamp
        self.name = name
        self.publicKey = publicKey
        self.enPrivateKey = enPrivateKey
        self.userID = userID
        super().__init__(**kwargs)

    @property
    def keyObj(self) -> Key:
        return self._keyObj

    @keyObj.setter
    def keyObj(self, value: Key):
        self._keyObj = value

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
    def delete_by_keyID(cls, keyID):
        try:
            instance = session.query(cls).filter_by(keyID=keyID).first()
            if instance:
                session.delete(instance)
                session.commit()
        except Exception as e:
            session.rollback()
            raise e
    
    @classmethod
    def get_all(cls) -> List['PrivateKeyRing']:
        instances = session.query(cls).all()
        return instances
    
    @classmethod
    def get_by_keyID(cls, keyID) -> 'PrivateKeyRing':
        instance = session.query(cls).filter_by(keyID=keyID).first()
        return instance

class PublicKeyRing(Base):
    __tablename__ = 'PublicKeyRing'

    keyID = Column(String, primary_key=True)
    timestamp = Column(TIMESTAMP, nullable=False, default=func.now())
    publicKey = Column(String, nullable=False)
    ownerTrust = Column(Integer, nullable=False)
    userID = Column(String, nullable=False)
    keyLegitimacy = Column(Integer, nullable=False)
    signature = Column(String, nullable=True)
    signatureTrust = Column(String, nullable=True)

    # ... add methods