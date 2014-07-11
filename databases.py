import functions
import json
import logging
import main
import webapp2

from google.appengine.ext import db
from google.appengine.api import users

# Wiki database
###############################
class Page(db.Model):
    # Wiki class for storing  page information in a database.
    title = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now_add = True)
    coords = db.GeoPtProperty()

    @staticmethod
    def parent_key(path):
        return db.Key.from_path('/root' + path, 'pages')

    @classmethod
    # this method operates on the class itself
    def by_id(cls, page_id, path):
    # returns a specific version of a page
        return Page.get_by_id(page_id, cls.parent_key(path))

    @classmethod
    def by_name(cls, title):
    # returns the page data via name key
        u = Page.all().filter('title =', title).get()

        return u

    @classmethod
    def by_path(cls, path):
        # returns all the pages with the path ancestor
        q = cls.all()
        q.ancestor(cls.parent_key(path))
        q.order("-created")
        
        return q

    @classmethod
    def recent_pages(cls, update=False):
        # looks up the cache for the last 5 pages created
        mc_key = "recent_pages"
        pages, age = functions.age_get(mc_key)

        # if there are no cached pages or an update is specified then look up 
        # the database
        if pages is None or update:
            logging.error("###########DB QUERY###########")
            pages = db.GqlQuery("SELECT * FROM Page ORDER BY created DESC LIMIT 5")
            pages = list(pages)
            functions.age_set(mc_key, pages)

        return pages, age

    @classmethod
    def cached_page(cls, title, update=False):
        # checks the cache for the page, individual versions are not stored
        mc_key = title
        page, age = functions.age_get(mc_key)

        # if the page doesn't exist in memcache then look up the page database
        # and store that data in the memcache
        if update or not page:
            logging.error("###########DB QUERY###########")

            # query the db for all the entites and return the most recent created
            page = Page.by_path(mc_key).get()

            # page = Page.by_name(mc_key)
            functions.age_set(mc_key, page)

            # recache the front page
            Page.recent_pages(update=True)

        return page, age    

    def render(self):
        self._render_text = self.content.replace("\n", "<br>")
        # calls the html template to render the post
        return main.render_str("post.html", p=self)

    def as_dict(self):
        time_fmt = "%c"
        d = {'title': self.title,
            'content': self.content,
            'created': self.created.strftime(time_fmt),
            'last_modified': self.last_modified.strftime(time_fmt)
        }
        return d

# User database
###############################
class User(db.Model):
    # User class for storing user information in a database.
    # Includes a name, hashed password and optional email.
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
    # returns the user data via id key
        return User.get_by_id(uid)

    @classmethod
    def by_name(cls, name):
    # returns the user data via name key
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
    # creates a User object
        pw_hash = functions.make_pw_hash(name, pw)
        return User(name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
    # looks up the user by name and checks if inputted password hashes into the same
    # string as the stored hashed password
        u = cls.by_name(name)
        if u and functions.valid_pw(name, pw, u.pw_hash):
            return u        

