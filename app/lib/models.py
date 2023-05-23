from sqlalchemy import TIMESTAMP, Column, Integer, String
from lib.keyring import Session, Base

session = Session()

class PrivateKeyRing(Base):
    __tablename__ = 'PrivateKeyRing'

    keyID = Column(String, primary_key=True)
    timestamp = Column(TIMESTAMP, nullable=False, default='now()')
    name = Column(String, nullable=False)
    publicKey = Column(String, nullable=False)
    enPrivateKey = Column(String, nullable=False)
    userID = Column(String, nullable=False)

    @classmethod
    def insert(cls, keyID, name, publicKey, enPrivateKey, userID):
        privateKeyRing = cls(keyID=keyID, name=name, publicKey=publicKey, enPrivateKey=enPrivateKey, userID=userID)
        session.add(privateKeyRing)
        session.commit()
        return privateKeyRing
    

class PublicKeyRing(Base):
    __tablename__ = 'PublicKeyRing'

    keyID = Column(String, primary_key=True)
    timestamp = Column(TIMESTAMP, nullable=False)
    publicKey = Column(String, nullable=False)
    ownerTrust = Column(Integer, nullable=False)
    userID = Column(String, nullable=False)
    keyLegitimacy = Column(Integer, nullable=False)
    signature = Column(String, nullable=True)
    signatureTrust = Column(String, nullable=True)

    @classmethod
    def insert(cls, keyID, name, publicKey, ownerTrust, userID, keyLegitimacy, signature=None, signatureTrust=None):
        privateKeyRing = cls(keyID=keyID, name=name, publicKey=publicKey, ownerTrust=ownerTrust, 
                             userID=userID, keyLegitimacy=keyLegitimacy, signature=signature, signatureTrust=signatureTrust)
        session.add(privateKeyRing)
        session.commit()
        return privateKeyRing