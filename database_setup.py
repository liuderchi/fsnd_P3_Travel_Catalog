"""database_setup.py
Created Date: 2016-01-24
Author: Derek Liu
Description: UDND P3: Item Catalog
"""

from sqlalchemy import Column
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import backref
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


class Region(Base):
    __tablename__ = 'region'
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'id'           : self.id
       }


class Spot(Base):
    __tablename__ = 'spot'
    name =Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(250))
    price = Column(String(8))
    type = Column(String(250))
    region_id = Column(Integer,ForeignKey('region.id'))
    # on delete region delete all spots
    region = relationship(
                Region,
                backref=backref("region", cascade="all,delete"))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'description'  : self.description,
           'id'           : self.id,
           'price'        : self.price,
           'type'         : self.type,
       }


#engine = create_engine('sqlite:///regionspot.db')
engine = create_engine('sqlite:///regionspot_users.db')
Base.metadata.create_all(engine)
