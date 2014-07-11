import databases
import hashlib
import hmac
import random
import re
import logging
import urllib2

from datetime import datetime, timedelta 
from string import letters

from google.appengine.ext import db
from google.appengine.api import memcache
from xml.dom import minidom

SECRET = "MAKI"
GMAPS_URL = "http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&"
IP_URL = "http://api.hostip.info/?ip="


# Regular expressions
###############################

# define regular expressions for each input type
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASSWORD_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")

def valid_input(username, regex):
	return regex.match(username)

# Hashing functions - passwords
###############################
def make_salt(length = 5):
	# returns a random string of 5 letters
	return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
	# if this is the first time hashing the user password then generate a salt string
	if not salt:
		salt = make_salt()

	# concatenate the name, password and salt string, then hash the result
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
	# checks if the password is valid by running it through the hashing function
	salt = h.split(',')[0]
	return h == make_pw_hash(name, password, salt)

# Hashing functions - cookies
###############################
def make_secure_val(val):
	# hashes a value(user's ID) with the global value secret
	return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())

def check_secure_val(secure_val):
	# checks that a value-hash pair is valid
	val = secure_val.split('|')[0]
	if secure_val == make_secure_val(val):
		return val

# Memcache functions
###############################
def age_set(key, val):
	# stores the key, value and save time in the memcache
	save_time = datetime.utcnow()
	memcache.set(key, (val, save_time))

def age_get(key):
	# check the memcache for the entry
	r = memcache.get(key)

	# if the entry exists, parse the data and compute the time since the entry was created
	if r:
		val, save_time = r
		age = (datetime.utcnow() - save_time).total_seconds()

	else:
		val, age = None, 0

	return val, age

def age_str(age):
	s = 'Queried %s seconds ago'
	age = int(age)
	if age == 1:
		s = s.replace('seconds', 'second')
	return s %(age)

# Googlemaps functions
###############################
def get_coords(ip):
	#ip = "210.139.85.154"
	url = IP_URL + ip
	content = None
	try:
		content = urllib2.urlopen(url).read()
	except URLError:
		return

	if content:
		# parse the xml and get the coords
		d = minidom.parseString(content)
		coords = d.getElementsByTagName("gml:coordinates")
		if coords and coords[0].childNodes[0].nodeValue:
			lon, lat = coords[0].childNodes[0].nodeValue.split(",")

			return db.GeoPt(lat, lon)

def gmaps_img(points):
    markers = '&'.join("markers=%s,%s" % (p.lat, p.lon) for p in points)
    return GMAPS_URL + markers

def gmaps_img2(point):
	markers = "markers="+str(point.lat)+","+str(point.lon)
	return GMAPS_URL + markers


    #markers = '&'.join("markers=%s,%s" % (point.lat, point.lon))


    # http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&markers=22.25,114.167&markers=53.3333,-6.25&markers=53.3333,-6.25&markers=37.402,-122.078
    # http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&22.25&114.167
    #http://maps.googleapis.com/maps/api/staticmap?size=380x263&sensor=false&22.25,114.167&markers=53.3333,-6.25
