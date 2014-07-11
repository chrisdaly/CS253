#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import databases
import functions
import json
import time
import logging

import jinja2
import os
import webapp2

from google.appengine.ext import db

# template loading code
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                                autoescape = True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.write(*a, **kw)

    def render_str(self, template, **params):
        # gives access to the variable user in templates
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
     
    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = "application/json; charset=UTF-8"
        self.write(json_txt)    

    def set_secure_cookie(self, name, val):
        # creates a secure cookie with a name, value and hashed value
        cookie_val = functions.make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        # looks up a cookie via its name and returns its value and hashed value
        cookie_val = self.request.cookies.get(name)
        return cookie_val and functions.check_secure_val(cookie_val)

    def login(self, user):
        # creates a cookie for the user when they login
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        # overwrites the login cookie when the user logs out
        self.response.headers.add_header(
            'Set-Cookie', 
            'user_id=; Path=/')

    def initialize(self, *a, **kw):
        # for every request the user is verified via cookie and instantiated as an object
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and databases.User.by_id(int(uid))

        if self.request.url.endswith(".json"):
            self.format = "json"
        else:
            self.format = "html"

    def notloggedin(self):
        # if the user is not logged in, redirect them
        if not self.user:
            self.redirect('/login')

class FrontPage(Handler):
    def get(self, path="", page="", pages="",age=""):

        cached_pages = databases.Page.recent_pages()

        if cached_pages[0]:
            pages, age = cached_pages
            age = functions.age_str(age)
            img_url= None
            # find which pages have coords
            l = len(cached_pages)
            points = []
            points = filter(None, (p.coords for p in pages))
            
            if points:
                img_url = functions.gmaps_img(points)

        if self.format == "html":
            self.render("front.html", title=path, pages=pages, age=age)

        elif self.format == "json":
            l = len(pages)
            for i in range(l):
                self.render_json(pages[i].as_dict())

# class WikiPage(Handler):
#     def get(self, path, age=""):
#         logging.error("~~~~~~~~~~~~~~~~~~~~~~~~~WIKIPAGE")

#         v = self.request.get("v")
#         page = None
#         if v:
#             if v.isdigit():
#                 page = databases.Page.by_id(int(v), path)

#             if not page:
#                 self.write("not valid")
#         else:
#             cached_page = databases.Page.cached_page(path)

#             if cached_page[0]:
#                 page, age = cached_page
#                 age = functions.age_str(age)

#         points = None
#         img_url = None

#         if page:
#             if page.coords:
#                 points = page.coords
#                 img_url = functions.gmaps_img2(points)

#             if self.format == "html":
#                 self.render("front.html", path=path, pages=[page], age=age, edit=True, img_url=img_url)

#             elif self.format == "json":
#                 self.render_json(page.as_dict())

#         else:
#             self.redirect("/_edit" + path)


# class EditPage(Handler):
#     def get(self, path, content=""):
#         logging.error("~~~~~~~~~~~~~~~~~~~~~~~~~EDITPAGE")

#         self.notloggedin()

#         v = self.request.get("v")
#         p = None
#         if v:
#             if v.isdigit():
#                 p = databases.Page.by_id(int(v), path)

#             if not p:
#                 self.write("not valid")
#         else:
#            # p = databases.Page.by_name(path)
#             p = databases.Page.by_path(path).get()
            
#         #self.render("editpage.html", entry=content, path=path, page=p)

#     def post(self, path=""):
#         self.notloggedin()
#         address = self.request.remote_addr
#         title = self.request.get("title")
#         content = self.request.get("content")
#         # can make this more efficient
#         old_page = databases.Page.by_name(path)
        

#         # if the page doesn't already exist and no content is typed, redirect
#         if not old_page:
#             if not content:
#                 self.redirect(path)

#         # if the page doesn't already exist then create a new one
#             else:
#                 #coords = functions.get_coords(address)
#                 page = databases.Page(parent= databases.Page.parent_key(path), 
#                                     title=title, content=content)

#                 page.put()
#                 time.sleep(1)

#                 # rerun the query and update the cached_page
#                 databases.Page.cached_page(path, update=True)

#         # if the page already exists but the content is edited, then make a sibling page
#         # ie a new version
#         elif old_page.content != content:
        
#             page = databases.Page(parent= databases.Page.parent_key(title),
#                                 title=title, content=content) # changed parent to title

#             page.put()
#             time.sleep(1)

#             # rerun the query and update the cached_page
#             databases.Page.cached_page(path, update=True)

#         time.sleep(1)
#         self.redirect(title)

class WikiPage(Handler):
    def get(self, title):
        # truncate the slash prepending the title
        title = title[1:]
        version = self.request.get("v")

        # check if there is a version specified and it's a number
        if version:
            if version.isdigit():
                page = databases.Page.by_id(int(version), title)

            # if that page-version doesn't exist then render an error page
            if not page:
                self.write("That version doesn't exist.")
                return

        # otherwise look up the last version of the page [last version not working]       
        else:
            #page = databases.Page.by_name(title)
            page = databases.Page.by_path(title).get()
        
        if page:
            if self.format == "html":
                self.render("page.html", path=title, pages=[page])

            elif self.format == "json":
                self.render_json(page.as_dict())

        else:
            self.write("Page not found.")

class EditPage(Handler):
    def get(self, title):
        # ensure login
        self.notloggedin()

        # truncate the slash prepending the title
        title = title[1:]
        version = self.request.get("v")

        # check if there is a version specified and it's a number
        if version:
            if version.isdigit():
                page = databases.Page.by_id(int(version), title)

            # if that page-version doesn't exist then render an error page
            if not page:
                self.write("That version doesn't exist.")
                return
        else:
            page = databases.Page.by_path(title).get()

        self.render("editpage.html", page=page)

    def post(self, title):
        # LOCK THE TITLE BAR SOMEHOW

        # truncate the slash prepending the title
        title = title[1:]

        content = self.request.get("content")

        if content:
            page = databases.Page(parent=databases.Page.parent_key(title),
                                title=title, content=content)
            page.put()
            time.sleep(1)
            self.redirect("/" + title)

class NewPage(Handler):
    def get(self):
        # ensure login
        self.notloggedin()

        logging.error("~~~~~~~~~~~~~~~~~~~~~~~~~NEWPAGE")
        #self.redirect("/_edit/newpage")

        self.render("editpage.html", entry="", path="", page=None)


    def post(self):
        title = self.request.get("title")
        content = self.request.get("content")

        if title and content:
            page = databases.Page(parent=databases.Page.parent_key(title),
                                title=title, content=content)
            page.put()
            time.sleep(1)
            self.redirect("/" + title)

class HistoryPage(Handler):
    def get(self, title):
        # truncate the slash prepending the title
        title = title[1:]

        logging.error("~~~~~~~~~~~~~~~~~~~~~~~~~HISTORYPAGE")
        self.notloggedin()

        q = databases.Page.by_path(title)
        q.fetch(limit = 100)

        pages = list(q)
        if pages:
            self.render("history.html", path=title, pages=pages, history=True)
        else:
            self.redirect("/_edit" + title)

class SignUp(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')
        error_status = False

        params = dict(username = self.username,
                      email = self.email)

        # check for invalid user name
        if not functions.valid_input(self.username, functions.USER_RE):
            params['error_username'] = "That's not a valid username."
            error_status = True

        # check for a valid password
        if (not functions.valid_input(self.password, functions.PASSWORD_RE)):
            params['error_password'] = "That wasn't a valid password."
            error_status = True

        # check for matching passwords
        if (self.password) and (not self.verify) or (self.password != self.verify):
            params['error_verify'] = "Your passwords didn't match."
            error_status = True

        # if an email is provided check if it's valid, otherwise don't flag an error
        if (self.email) and not functions.valid_input(self.email, functions.EMAIL_RE):
            params['error_email'] = "That's not a valid email."
            error_status = True

        # if errors are present then redirect to a welcome page
        if error_status:
            self.render('signup.html', **params)

        # if there are no errors go to a welcome page
        if error_status == False:
            self.form_ok()

    def form_ok(self):
        # check the user database for the username
        u = databases.User.by_name(self.username)
        # if the user already exists then re-render the page with an error
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username = msg)
        # the that username does not already exist then register it and store it on the database
        else:
            u = databases.User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/')

class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = databases.User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = 'Invalid login'
            self.render('login.html', error = msg)

class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/')

class Search(Handler):
    def get(self):
        logging.error("~~~~~~~~~~~~~~~~~~~~~~~~~SEARCH")
        
        # extract the search parameter from the form
        q = self.request.get("q")

        # redirect to the search, and let the WikiPage handler check if it's valid
        if q:
            self.redirect("/" + q)

class DeletePage(Handler):
    def get(self, title):
        logging.error("~~~~~~~~~~~~~~~~~~~~~~~~~DELETE")
        # truncate the slash prepending the title
        title = title[1:]

        self.write(title)
        version = self.request.get("v")


        # check if there is a version specified and it's a number
        if version:
            if version.isdigit():
                page = databases.Page.by_id(int(version), title)

            # if that page-version doesn't exist then render an error page
            if not page:
                self.write("That version doesn't exist.")
                return

        # otherwise look up the last version of the page [last version not working]       
        else:
            self.write(title)
            page_key = db.Page.from_path('Page', 'title')
            page = db.get(page_key)

            # ...

        page.delete()


class Flare(Handler):
    def get(self):
        self.render("test.html")

# regular expression for webpages
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

app = webapp2.WSGIApplication([
                                ("/", FrontPage),
                                ('/signup/?', SignUp),
                                ('/login/?', Login), 
                                ('/logout/?', Logout),
                                ('/_search', Search),  
                                ('/_history' + PAGE_RE, HistoryPage),
                                ('/?(?:\.json)?', FrontPage),
                                ("/flare", Flare),
                                ("/_newpage", NewPage),
                                ("/_edit" + PAGE_RE, EditPage),
                                ("/_delete" + PAGE_RE, DeletePage),
                                (PAGE_RE + ".json", WikiPage),
                                (PAGE_RE, WikiPage)
                                ],  
                                debug=True)


# TO DO:
# reffer to the previous page after login/signup/logout
# d3 graph
# atm, updating an entry does NOT effect its coords, this could be solved 
# by adding an ancestor and children
# https://developers.google.com/appengine/docs/python/datastore/entities
# look up the last version of a page when no version is specified
# delete button
# fix issue with urls having spaces "/chris%20is%20cool"
# create author field for page entity, to look up user's "my contributions"
# reintroduce caching
