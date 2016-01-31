from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database_setup import Base
from database_setup import User
from database_setup import Region
from database_setup import Spot


#engine = create_engine('sqlite:///regionspot.db')
engine = create_engine('sqlite:///regionspot_users.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


def session_add_commit(session, obj):
    session.add(obj)
    session.commit()

user_template = User(name="Templa Foo",
                     email="template@temp.com",
                     picture="http://www.w3schools.com/tags/smiley.gif")
session_add_commit(session, user_template)

region_one = Region(name='Taiwan', user_id=1)
session_add_commit(session, region_one)
spot_one = Spot(name='Taipei 101',
                description='this is the tallest building in Taiwan',
                type='sightseeing',
                price='$100',
                region=region_one,
                user_id=1)
session_add_commit(session, spot_one)
spot_two = Spot(name='Shi-Lin Night Market',
                description='Delicious snacks in Taipei',
                type='food',
                price='$50',
                region=region_one,
                user_id=1)
session_add_commit(session, spot_two)


region_two = Region(name='France', user_id=1)
session_add_commit(session, region_two)
spot_one = Spot(name='Eiffel Tower',
                description='must-see in Fance',
                type='sightseeing',
                price='$400',
                region=region_one,
                user_id=1)
session_add_commit(session, spot_one)
