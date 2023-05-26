from typing import List
from sqlalchemy import TIMESTAMP, Column, Integer, String, func
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

    @classmethod
    def insert(cls, keyID, name, publicKey, enPrivateKey, userID):
        try:
            privateKeyRing = cls(keyID=keyID, name=name, publicKey=publicKey, enPrivateKey=enPrivateKey, userID=userID)
            session.add(privateKeyRing)
            session.commit()
            return privateKeyRing
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
                return True
        except Exception as e:
            session.rollback()
            raise e
    
    @classmethod
    def getAll(cls) -> List['PrivateKeyRing']:
        instances = session.query(cls).all()
        return instances

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

    @classmethod
    def insert(cls, keyID, name, publicKey, ownerTrust, userID, keyLegitimacy, signature=None, signatureTrust=None):
        publicKeyRing = cls(keyID=keyID, name=name, publicKey=publicKey, ownerTrust=ownerTrust, 
                             userID=userID, keyLegitimacy=keyLegitimacy, signature=signature, signatureTrust=signatureTrust)
        session.add(publicKeyRing)
        session.commit()
        return publicKeyRing
    
    @classmethod
    def getAll(cls) -> List['PublicKeyRing']:
        instances = session.query(cls).all()
        return instances