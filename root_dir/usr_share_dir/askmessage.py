#------------------------------------------------------------------------------
#	askmessage.py
#
#	(C) 2001-2006 by Marco Paganini (paganini@paganini.net)
#
#   This file is part of ASK - Active Spam Killer
#
#   ASK is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   ASK is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with ASK; if not, write to the Free Software
#   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Updates and bug fixes:
#	by celer, 2012 (for python2), by william wortel, 2019 (for python3)
#   File I/O in this module is binary by default to handle utf-8 encoding.
#	$Id: askmessage.py,v 1.106 2006/01/09 04:22:26 paganini Exp $
#------------------------------------------------------------------------------

import os
import sys
import codecs
import hashlib
import re
import time
import tempfile
import email
from email.header import decode_header
from html.parser import HTMLParser
from pathlib import Path
import asklog
import askconfig
import askmail
import asklock

#------------------------------------------------------------------------------

class AskMessage:
	"""
	This is the main ASK class. 
	
	Attributes:

	- tmpf_path:     Path of temporary file containing the mail message
	- wrkf:			 File Object with tmpf_path
	- binary_digest: MD5 digest in binary format
	- ascii_digest:  MD5 digest in ascii format
	- conf_md5:      MD5 digest found in the subject

	- msg:	   Message object
	- md5sum:  md5sum object
	- log:     LOG object
	- config:  CONFIG object
	- mail:    MAIL object
	"""

	#----------------------------------------------------------------------------------
	def __init__(self, config, log):
		"""
		Initializes the class instance. We need at least a valid CONFIG object 
		and a valid LOG object.
		"""
		## Initialize the LOG, CONFIG and MAIL objects


		self.log			= log
		self.config			= config
		self.mail			= askmail.AskMail(config, log)
		self.mail.fullname	= self.config.rc_myfullname
		tdir				= self.config.rc_tmpdir + '/'

		## tmpf_path must be on the same filesystem as ASK's private dir!
		## We'll use 'rename' later to change it to the definitive location

		tmpf_fh, self.tmpf_path = tempfile.mkstemp(suffix='.' + str(os.getpid()) + '.msg', prefix=tempfile.gettempprefix() +  '.', dir=tdir, text=False)
		self.tmpPath		= Path(self.tmpf_path)
		self.wrkf			= ''
		self.email_obj		= ''
		self.binary_digest	= ''
		self.ascii_digest	= ''
		self.list_match		= ''
		self.set_conf_md5('')

	#----------------------------------------------------------------------------------
	def __del__(self):

		if self.wrkf:
			self.wrkf.close()

		if self.tmpPath.exists():
			self.tmpPath.unlink()

		#self.log.write(10, "  __del__(): Removing %s" % self.tmpf_path)

	#----------------------------------------------------------------------------------
	def set_conf_md5(self, md5):
		"""
		Allows external callers to change the notion of the 'conf_md5',
		or the md5sum retrieved from the subject line. This is useful
		for instance, when you wish to process different (queued) files
		using the methods in this class.
		"""

		self.config_md5 = md5
		
	#----------------------------------------------------------------------------------
	def	read(self, file_path):
		"""
		This function will read all data from the passed 'file_path' into a
		temporary file. This file will then be used for all sorts of operations
		needed by this class. 
		"""
		# open(file, mode='r', buffering=-1, encoding=None, errors=None, newline=None, closefd=True, opener=None)
		if file_path == sys.stdin :
			rx_orig = sys.stdin.buffer.read()
		else:
			rx_obj = open(file_path, mode='rb')
			rx_orig = rx_obj.read()
			rx_obj.close()

		rx_hdrs , rx_body = rx_orig.split(b'\n\n', maxsplit=1)
		## Remove X-ASK-Action headers
		## exactly one newline char at the end (it might be followed by an empty line signalling body start) 
		rx_hdrs = re.sub(b'X-ASK-Action:.*\w\x0a{1}?', b'',rx_hdrs)

		rx_msg = bytearray()
		rx_msg.extend(rx_hdrs)
		rx_msg.extend(b'\n\n')
		rx_msg.extend(rx_body)
		## Create a new MD5 object
		self.md5sum = hashlib.md5()
		self.md5sum.update(rx_msg)

		## Add the md5key to the hash
		if (self.config.rc_md5_key != ''):
			self.md5sum.update(self.config.rc_md5_key.encode('utf-8'))

		##  and produce the ASCII digest
		self.ascii_digest = ''
		binary_digest = self.md5sum.digest()
		for ch in range(0,len(binary_digest)):
			self.ascii_digest = self.ascii_digest + "%02.2x" % binary_digest[ch]

		## create Message object with headers only (ASK does not filter on body contents)
		self.email_obj = email.message_from_bytes(rx_hdrs)

		# fill the temporary file with the processed read email
		self.wrkf = open(self.tmpf_path, mode = 'wb')
		self.wrkf.write(rx_msg)
		self.wrkf.close()

	#----------------------------------------------------------------------------------
	def decode_address(self, hdr):
		"""
		The addresses may be a combination of free text followed by an email address in ascii.
		The free part is decoded from its parts that may have different encodings and encoded to utf-8.
		This decoding is done only when text is present followed by an email address. 
		"""

		(addr_name, addr_mail) = email.utils.parseaddr(hdr)
		
		## Decode address name and return if found
		if addr_mail and addr_name:
			addr_name = decode_header(addr_name)
			decoded = ''
			for stuple in addr_name:
				if stuple[1] == None:
					decoded += stuple[0]
				else:
					decoded += stuple[0].decode(stuple[1])
			addr_name = decoded
		
		return( addr_name.rstrip(), addr_mail.rstrip() )

	#----------------------------------------------------------------------------------
	def	get_real_sender(self):
		"""
		This is just like "get_sender", but the "X-Primary-Address" is not taken into
		account. Useful for cases where you don't want to use this address (when sending
		an email back, for instance).
		"""

		return(self.get_sender(ignore_header = "X-Primary-Address"))

	#----------------------------------------------------------------------------------
	def get_sender(self, ignore_header=""):
		"""
		Returns a tuple in the format (sender_name, sender_email). Some processing is
		done to treat X-Primary-Address/Resent-From/Reply-To/From. Headers in "ignore_header"
		are not checked.
		"""

		headers = ["X-Primary-Address", "Resent-From", "Reply-To", "From"];

		## Remove unwanted headers
		def fn_remove(x, y = ignore_header): return(x != y)
		headers = filter(fn_remove, headers)

		for hdr in headers:
			(sender_name, sender_mail) = self.decode_address(self.email_obj.get(hdr))
			if sender_mail and sender_name:
				break

		return(sender_name.rstrip(), sender_mail.rstrip())

	#----------------------------------------------------------------------------------
	def get_recipients(self):
		"""
		Returns a list of tuples in the format (sender_name, sender_email). Note that
		the list includes the contents of the TO, CC and BCC fields.
		"""

		## Master list of recipients
		recipients = []

		to_list = [ self.email_obj.get("To") ]		## To:
		if to_list:
			for item in to_list:
				recipients.append( self.decode_address(item) )
		cc_list  = [ self.email_obj.get("Cc") ]		## Cc:
		if cc_list:
			for item in cc_list:
				recipients.append( self.decode_address(item) )
		bcc_list = [ self.email_obj.get("Bcc") ]	## Bcc:
		if bcc_list:
			for item in bcc_list:
				recipients.append( self.decode_address(item) )

		return(recipients)

	#----------------------------------------------------------------------------------
	def get_subject(self):
		"""
		Returns the subject of the message, or '' if none is defined, as utf-8 encoded string.
		Only primary subject section is used and decoded via its detected encoding.
		"""

		subject = decode_header(self.email_obj.get("Subject"))
		decoded = ''

		for stuple in subject:
			if stuple:
				if stuple[1] == None:
					# no encoding can result in string type or bytes type.
					# when bytes, decode it to string (utf-8 in Python3)
					if type(stuple[0]) == type(b''):
						decoded += str( stuple[0], 'utf-8')
					if type(stuple[0]) == type(''):
						decoded += stuple[0]
				else:
					decoded += str( stuple[0], stuple[1])
		
		return(decoded)

	#----------------------------------------------------------------------------------
	def get_date(self):
		"""
		Returns a tuple containing the broken down date (from the "Date:" field)
		The tuple contains (year, month, day, hour, minute, second, weekday, julianday,
		dst_flag) and can be fed directly to time.mktime or time.strftime.
		"""

		## Lots of messages have broken dates
		try:
			date_tpl = email.utils.parsedate(self.email_obj.get("Date"))
		except:
			date_tpl = ''

		return(date_tpl)

	#------------------------------------------------------------------------------
	def get_received_spf(self):
		"""
		Returns the "SPF" result or '' if none is defined.
		"""

		return(self.email_obj.get("Received-SPF"))

	#------------------------------------------------------------------------------
	def get_message_id(self):
		"""
		Returns the "Message-Id" field or '' if none is defined.
		"""

		return(self.email_obj.get("Message-Id"))

	#------------------------------------------------------------------------------
	def __inlist(self, filenames, sender=None, recipients=None, subj=None):
		"""
		Checks if sender email, recipients or subject match one of the regexps
		in the given filename array/tuple. If sender/recipient/subject are not
		specified, the defaults for the current instance will be used.
		"""

		## Fill in defaults
		if sender == None:
			sender = self.get_sender()[1]

		if recipients == None:
			recipients = self.get_recipients()

		if subj == None:
			subj = self.get_subject()

		## If the sender is one of our emails, we immediately return true.
		## This allows being precise with "from ouremail@ourdomain.com" without having to
		## worry about coarse matching "from @ourdomain.com"

		if self.is_from_ourselves(sender):
			self.log.write(1, "  __inlist(): We are the sender (%s). Is SPF OK ?." % sender)
			rcvdspf = self.get_received_spf()
			if (rcvdspf == 'pass'):
				self.log.write(1, "  __inlist(): SPF: %s" % rcvdspf)
				self.list_match = "We are confirmed sender"
				return 1
			else:
				self.log.write(1, "  __inlist(): but SPF ( %s ) did not pass." % rcvdspf)
				self.list_match = ""
				return 0

		## Test each filename in turn

		for fname in filenames:

			## If the file does not exist, ignore
			self.log.write(5, "  __inlist(): filename=%s, sender=%s, dest=%s, subject=%s"% (fname, sender, recipients, subj))

			if (os.access(fname, os.R_OK) == 0):
				self.log.write(5, "  __inlist(): %s does not exist (or is unreadable). Ignoring..." % fname)
				continue

			fh = open(fname, mode='rb')
			sdata = fh.read().decode('latin1')
			fh.close()

			## cycle through white/ignore list lines
			for entry in sdata.split('\n'):
				buf = entry.rstrip().lower()

				## Ignore comments and blank lines
				if ( len(buf) == 0 ) or ( buf[0] == '#' ):
					self.log.write(20, "  __inlist(): ignoring line [%s]" % buf)
					continue

				## self.log.write(20,"  __inlist(): regexp=[%s]" % buf)
				## "from re"    matches sender
				## "to re"      matches destination (to, bcc, cc)
				## "subject re" matches subject
				## "header re"  matches a full regexp in the headers
				## "re"         matches sender (previous behavior)

				## find lines list entry category (from, to, subject, header) 
				strlist = []
				## FROM
				res = re.match("from\s*(.*)", buf, re.IGNORECASE)
				if res:
					## No blank 'from'
					if not res.group(1):
						continue

					regex   = self.__regex_adjust(res.group(1))
					strlist.append(sender)
				else:
					## to
					res = re.match("to\s*(.*)", buf, re.IGNORECASE)
					if res:
						regex = self.__regex_adjust(res.group(1))
						## Append all recipients
						for (recipient_name, recipient_email) in recipients:
							strlist.append(recipient_email)
					else:
						## subject
						res = re.match("subject\s*(.*)", buf, re.IGNORECASE)

						if res:
							regex = res.group(1)
							strlist.append(subj)
						else:
							## header
							res = re.match("header\s*(.*)", buf, re.IGNORECASE)
							if res:
								regex = res.group(1)
								for hdr in self.email_obj.items():
									## reduce multi-line headers to just the first line
									parts = hdr[1].split('\n')
									strlist.append( hdr[0] + ': ' + parts[0] )
							else:
								regex = self.__regex_adjust(buf)
								strlist.append(sender)

				## Match...

				for ustr in strlist:
					try:
						if (regex and re.search(regex, ustr, re.IGNORECASE)):
							self.log.write(5, "  __inlist(): found with re=%s" % buf)
							self.list_match = buf
							return 1
					except:
						self.log.write(1,"  __inlist(): WARNING: Invalid regular expression: \"%s\". Ignored." % regex)

		self.list_match = ""
		return 0

	#------------------------------------------------------------------------------
	def __regex_adjust(self, ustr):
		"""
		Returns the "adjusted" regular expression to be used in matching
		email items. If the regular expression itself matches xxx@xxx, we
		assume a full address match is desired (we try to match using ^re$ or
		else r@boo.org would also match spammer@boo.org) unless the user has given
		either ^ and/or $ we respect that definition as is.
		The ustr variable is supposed to be a utf-8 compliant string, Python3 only
		"""

		if re.search('.+@.+', ustr) and ( ustr.find('^') != -1 or ustr.find('$') != -1):
			ustr = ustr.rstrip('$')
			ustr = ustr.lstrip('^')
			return( '^' + ustr + '$' )
		else:
			return(ustr)

	#------------------------------------------------------------------------------
	def is_from_ourselves(self, email = None):
		"""
		Returns true if the sender is one of our emails. Use 'email' instead of
		the current sender if specified.
		"""

		if not email:
			email = self.get_sender()[1].lower()

		for lvar in self.config.rc_mymails:
			if email in lvar.lower():
				return 1

		return 0
	
	#------------------------------------------------------------------------------
	def is_in_whitelist(self):
		"""
		Returns true if this message is in the whitelist. False otherwise
		"""

		if self.__inlist(self.config.rc_whitelist):
			return 1
		else:
			return 0

	#------------------------------------------------------------------------------
	def is_in_ignorelist(self):
		"""
		Returns true if this message is in the ignorelist. False otherwise
		"""

		if self.__inlist(self.config.rc_ignorelist):
			return 1
		else:
			return 0

	#------------------------------------------------------------------------------
	def has_our_key(self):
		"""
		Returns true if this message contains our mailkey. False otherwise
		"""

		if self.__contains_string(self.config.rc_mailkey):
			return 1
		else:
			return 0

	#------------------------------------------------------------------------------
	def is_from_mailerdaemon(self):
		"""
		Returns true if this message comes from MAILER-DAEMON. False otherwise
		"""

		if re.match("mailer-daemon|postmaster@|<>", self.get_sender(ignore_header = "Reply-To")[1], re.IGNORECASE):
			return 1
		else:
			return 0

	#------------------------------------------------------------------------------
	def sent_by_ask(self):
		"""
		Looks for the X-AskVersion rfc822 header. If one is found, we assume ASK
		sent the message and we return true. Otherwise, we return false.
		"""

		if self.__contains_string("^X-AskVersion:"):
			return 1
		else:
			return 0

	#------------------------------------------------------------------------------
	def valid_smtp_sender(self):
		"""
		Uses mail.smtp_validate to check the sender's address. Return true if 
		probably valid, 0 if definitely invalid.
		"""

		ret = self.mail.smtp_validate(email         = self.get_sender()[1], 
									  envelope_from = self.get_matching_recipient())

		self.log.write(5, "  valid_smtp_sender: SMTP authentication returned %d" % ret)

		## Returns possibly valid in case of errors.

		if ret != 0:
			return 1
		else:
			return 0
			
	#------------------------------------------------------------------------------
	def	deliver_mail(self, x_ask_info="Delivering Mail"):
		"""
		Delivers the current mail to the mailbox contained in self.config.rc_mymailbox
		or to stdout if in filter or procmail mode.
		"""

		## Deliver to stdout if using procmail/filter
		if self.config.procmail_mode or self.config.filter_mode:
			mailbox = "-"
		else:
			mailbox = self.config.rc_mymailbox

		self.log.write(1, "  deliver_mail(): Delivering mail")
		self.mail.deliver_mail_file(mailbox,
									self.tmpf_path,
									x_ask_info = x_ask_info,
									custom_headers = [ "X-ASK-Auth: " + self.generate_auth() ])

		return 0

	#------------------------------------------------------------------------------
	def	junk_mail(self, x_ask_info="Junk"):
		"""
		Queues the current mail with a status of "Junk" or delivers to
		rc_junkmailbox if is defined in the config file.
		"""

		if self.config.rc_junkmailbox:
			self.log.write(1,"  junk_mail(): Saving message to %s" % self.config.rc_junkmailbox)
			self.mail.deliver_mail_file(self.config.rc_junkmailbox,
										self.tmpf_path,
										x_ask_info = x_ask_info,
										custom_headers = [ "X-ASK-Auth: " + self.generate_auth() ])
		else:
			self.log.write(1, "  junk_mail(): Queueing Junk Message")
			self.queue_mail(x_ask_info = x_ask_info)

		return 0

	#------------------------------------------------------------------------------
	def	bulk_mail(self, x_ask_info="Bulk"):
		"""
		Queues the current mail with a status of "Bulk" or delivers to
		rc_bulkmailbox if is defined in the config file.
		"""

		if self.config.rc_bulkmailbox:
			self.log.write(1,"  bulk_mail(): Saving message to %s" % self.config.rc_bulkmailbox)
			self.mail.deliver_mail_file(self.config.rc_bulkmailbox,
										self.tmpf_path,
										x_ask_info = x_ask_info,
										custom_headers = [ "X-ASK-Auth: " + self.generate_auth() ])
		else:
			self.log.write(1, "  bulk_mail(): Queueing Bulk Message")
			self.queue_mail(x_ask_info = x_ask_info)

		return 0

	#------------------------------------------------------------------------------
	def queue_mail(self, x_ask_info="Message Queued"):
		"""
		Queues the current message. The queue directory and calculated MD5
		are used to generate the filename. Note that the MD5 reflect the original
		contents of the message (not the queued one, as headers are added as needed).

		If the message queue directory (rc_askmsg) ends in "/", we assume the
		queue will be in mqueue format.
		"""

		self.log.write(5,  "  queue_mail(): x_ask_info = %s" % x_ask_info)
		self.log.write(5,  "  queue_mail(): The MD5 checksum for %s is %s" % (self.tmpf_path, self.ascii_digest))

		## If the msgdir ends in "/" we assume a Maildir style queue. If
		## not, we have a regular queue.

		if self.config.queue_is_maildir:
			self.log.write(5, "  queue_mail(): Maildir format. Queue dir = %s" % self.config.rc_msgdir)
			self.mail.deliver_mail_file(self.config.rc_msgdir,
										self.tmpf_path,
										x_ask_info = x_ask_info,
										uniq = self.ascii_digest,
										custom_headers = [ "X-ASK-Auth: " + self.generate_auth() ])
		else:
			queueFileName = self.queue_file()
			self.log.write(5, "  queue_mail(): Mailbox format. Queue file = %s" % queueFileName)
			self.mail.deliver_mail_file(queueFileName,
										self.tmpf_path,
										x_ask_info,
										custom_headers = [ "X-ASK-Auth: " + self.generate_auth() ])
		
		return 0

	#------------------------------------------------------------------------------
	def send_confirmation(self):
		"""
		Sends a confirmation message back to the sender.
		"""

		queueFileName = self.queue_file()

		self.mail.mailfrom = self.get_matching_recipient()

		self.log.write(1, "  send_confirmation(): Sending confirmation from %s to %s" % (self.mail.mailfrom, self.get_real_sender()[1]))

		## Add Precedence: bulk and (if appropriate) "In-Reply-To"

		header_list = [ "X-ASK-Auth: %s" % self.generate_auth(), "Precedence: bulk", "Content-Type: text/plain; charset=\"iso-8859-1\"", "Content-Transfer-Encoding: 8bit" ]

		msgid = self.get_message_id()

		if msgid:
			header_list.append("In-Reply-To: %s" % msgid)
		
		if (self.__check_confirm_list(self.get_real_sender()[1])):
			self.mail.send_mail(self.get_real_sender()[1],
							"Please confirm (conf#%s)" % self.ascii_digest,
							self.config.rc_confirm_filenames,
							[queueFileName],
							custom_headers = header_list,
							max_attach_lines = self.config.rc_max_attach_lines)

			self.log.write(1, "  send_confirmation(): Confirmation sent to %s..." % self.get_real_sender()[1])
		else:
			self.log.write(1, "  send_confirmation(): too many confirmations already sent to %s..." % self.get_real_sender()[1])

	#------------------------------------------------------------------------------

	def	__check_confirm_list(self, address):
		"""
		Adds address to the list of confirmation targets.
		Returns true if this confirmation should be sent.
		Returns false otherwise.
		"""

		name = address + "\n"

		queue_file_name = "%s/.ask-loop-control.dat"  % self.config.rc_askdir

		## Confirmation list file will be created if it does not exist
		if not os.path.exists(queue_file_name):
			queue_file_handle = open(queue_file_name, "w")
			queue_file_handle.close()

		## Lock
		queue_file_handle = asklock.AskLock()
		lockf = ""

		if self.config.rc_lockfile != "":
			lockf = self.config.rc_lockfile + "." + os.path.basename(queue_file_name)
		else:
			lockf = queue_file_name

		queue_file_handle.open(queue_file_name, "r+", lockf)

		## Read all stuff from .ask-loop-control.dat

		if os.path.exists(queue_file_name):
			queue_file_handle.seek(0)
			confirm_list = queue_file_handle.readlines()
		else:
			confirm_list = []

		confirm_list.append(name)

		## Trim list
		if len(confirm_list) > self.config.rc_max_confirmation_list:
			del confirm_list[0:self.config.rc_max_confirmation_list - self.config.rc_min_confirmation_list]

		## Rewrite trimmed list and release lock

		queue_file_handle.seek(0)
		queue_file_handle.truncate(0)
		queue_file_handle.writelines(confirm_list)

		queue_file_handle.close()

		## More than max_confirmations?
		if (confirm_list.count(name) > self.config.rc_max_confirmations):
			return 0

		return 1
	#------------------------------------------------------------------------------

	def	queue_file(self, md5str=""):
		"""
		Returns the full path to the queue file of the current message
		(self.ascii_digest). The 'md5' parameter can be used to override
		the MD5 checksum. If the queue is in maildir format, the queue
		directory will be opened and the first file containing the MD5
		will be returned.
		"""

		if not md5str:
			md5str = self.ascii_digest

		if self.config.queue_is_maildir:

			## Original Path if Maildir
			maildir = self.config.rc_msgdir.replace("/cur", "")
			maildir = maildir.replace("/new", "")
			maildir = maildir.replace("/tmp", "")

			## /cur
			file_list = filter(lambda x,md5str_in = md5str: (x.find(md5str_in) != -1), os.listdir(maildir + "cur"))

			if len(file_list) != 0:
				return(os.path.join(maildir + "cur", file_list[0]))

			## /new
			file_list = filter(lambda x,md5str_in = md5str: (x.find(md5str_in) != -1), os.listdir(maildir + "new"))

			if len(file_list) != 0:
				return(os.path.join(maildir + "new", file_list[0]))

			## Nothing found, return blank
			return ""

		else:
			return "%s/ask.msg.%s" % (self.config.rc_msgdir, md5str)

	#------------------------------------------------------------------------------

	def	discard_mail(self, x_ask_info="Discard", mailbox = '', via_smtp = 0):
		"""
		This method will deliver the current message to stdout and append a
		'X-ASK-Action: Discard' header to it. This will only happen if we're
		operating in "filter" mode.
		"""

		if not self.config.filter_mode:
			return

		self.log.write(10, "  discard_mail: Sending email to stdout with X-ASK-Action: Discard")

		self.mail.deliver_mail_file("-",
									self.tmpf_path,
									x_ask_info = x_ask_info,
									custom_headers = [ "X-ASK-Action: Discard",
													   "X-ASK-Auth: " + self.generate_auth() ])

		return 0

	#------------------------------------------------------------------------------

	def	dequeue_mail(self, x_ask_info="Message dequeued", mailbox = '', via_smtp = 0):
		"""
		Dequeues (delivers) mail in the queue directory to the current user.
		The queued message will be directly appended to the mailbox. The 'mailbox'
		parameter can be specified to force delivery to something different than
		the default config.rc_mymailbox.
		"""

		if not mailbox:
			## Deliver to stdout if using procmail/filter
			if self.config.procmail_mode or self.config.filter_mode:
				mailbox = "-"
			else:
				mailbox = self.config.rc_mymailbox

		queueFileName = self.queue_file(self.config_md5)
		self.log.write(1, "  dequeue_mail(): Delivering mail from %s to mailbox %s" % (queueFileName, mailbox))

		if via_smtp:
			self.mail.mailfrom = self.config.rc_mymails[0]

			self.mail.send_mail_file(self.config.rc_mymails[0],
								  	 queueFileName,
									 x_ask_info = x_ask_info,
									 custom_headers = [ "X-ASK-Auth: " + self.generate_auth() ])
		else:
			self.mail.deliver_mail_file(mailbox,
										queueFileName,
										x_ask_info = x_ask_info,
										custom_headers = [ "X-ASK-Auth: " + self.generate_auth() ])

		os.unlink(queueFileName)

		return 0

	#------------------------------------------------------------------------------

	def	delete_mail(self, x_ask_info="No further info"):
		"""
		Deletes queued file in the queue directory.
		"""

		queueFileName = self.queue_file(self.config_md5)
		os.unlink(queueFileName)

		self.log.write(1, "  delete_mail(): Queued file %s deleted" % queueFileName)

		return 0

	#------------------------------------------------------------------------------
	def	is_queued(self):
		"""
		Checks if a queued message exists matching the current MD5 signature.
		"""

		queueFileName = self.queue_file()

		if (os.access(queueFileName, os.F_OK) == 1):
			self.log.write(1, "  is_queued(): File %s found. Message is queued" % queueFileName)
			return 1
		else:
			self.log.write(1, "  is_queued(): File %s not found. Message is not queued" % queueFileName)
			return 0

	#------------------------------------------------------------------------------
	def	confirmation_msg_queued(self):
		"""
		Returns true if the current message is a confirmation message AND
		a queued message exists. False otherwise.
		"""

		queueFileName = self.queue_file(self.config_md5)

		if (os.access(queueFileName, os.F_OK) == 1):
			self.log.write(1, "  confirmation_msg_queued(): File %s found. Message is queued" % queueFileName)
			return 1
		else:
			self.log.write(1, "  confirmation_msg_queued(): File %s not found. Message is not queued" % queueFileName)
			return 0

	#------------------------------------------------------------------------------
	def is_confirmation_return(self):
		"""
		Checks whether the message subject is a confirmation. If so, self.config_md5
		will be set to the MD5 hash found in the subject true will be returned.
		"""

		subject = self.get_subject()

		self.log.write(10, "  is_confirmation_return(): Subject=" + subject)

		res = re.search("\(conf[#:]([a-f0-9]{32})\)", subject, re.IGNORECASE)

		if (res == None):
			self.log.write(1, "  is_confirmation_return(): Didn't find conf#MD5 tag on subject")
			self.config_md5 = ''
			return 0
		else:
			self.log.write(1, "  is_confirmation_return(): Found conf$md5 tag, MD5=%s" % res.group(1))
			self.config_md5 = res.group(1)
			return 1

	#------------------------------------------------------------------------------
	def add_queued_msg_to_whitelist(self):
		"""
		Adds the sender in the message pointed to by 'conf_md5' to the whitelist.
		"""

		queueFileName   = self.queue_file(self.config_md5)

		## Create a new AskMessage instance with the queued file
		aMessage        = AskMessage(self.config, self.log)
		
		aMessage.read(queueFileName)
		
		self.log.write(1, "  add_queued_msg_to_whitelist(): Adding message %s to whitelist" % queueFileName)
		aMessage.add_to_whitelist()

	#------------------------------------------------------------------------------
	def add_to_whitelist(self, regex = None):
		"""
		Adds the current sender or the optional 'regex' to the whitelist.
		"""

		if not regex:
			regex = self.get_sender()[1]
			
		self.__add_to_list(self.config.rc_whitelist, regex)

		return 0

	#------------------------------------------------------------------------------
	def add_to_ignorelist(self, regex = None):
		"""
		Adds the current sender or the optional 'regex' to the ignorelist.
		"""

		if not regex:
			regex = self.get_sender()[1]

		self.__add_to_list(self.config.rc_ignorelist, regex)

		return 0

	#------------------------------------------------------------------------------
	def remove_from_whitelist(self, email):
		"""
		Remove the passed email from the whitelist.
		"""

		self.__remove_from_list(self.config.rc_whitelist, email)
		return 0

	#------------------------------------------------------------------------------
	def remove_from_ignorelist(self, email):
		"""
		Remove the passed email from the ignorelist.
		"""

		self.__remove_from_list(self.config.rc_ignorelist, email)
		return 0

	#-----------------------------------------------------------------------------
	def __add_to_list(self, filenames, email=None):
		"""
		Adds the specified 'email' to the first filename in the array 'filenames'.
		Defaults to using the current sender if none is specified.
		"""

		## Defaults
		if email == None:
			email = self.get_sender()[1]

		## Make sure it's not one of our own emails...
		if self.is_from_ourselves(email):
			self.log.write(1, "  __add_to_list(): \"%s\" is listed as one of our emails. It will not be added to the list (%s)" % (email, filenames[0]))
			return -1

		## Do not add if it's already there... (Compare sender only)
		if self.__inlist(filenames,
						 sender     = email,
						 recipients = [("*IGNORE*","*IGNORE*")],
						 subj       = "*IGNORE*"):
			self.log.write(1, "  __add_to_list(): \"%s\" is already present in \"%s\". It will not be re-added" % (email, filenames[0]))
			return -1

		self.log.write(10, "  __add_to_list(): filename=%s, email=%s" % (filenames[0], email))

		lck = asklock.AskLock()

		lockf = ""
		if self.config.rc_lockfile != "":
			lockf = self.config.rc_lockfile + "." + os.path.basename(filenames[0])

		lck.open(filenames[0], "a", lockf)
		
		## We suppose the file is unlocked when we get here...
		lck.write("from " + self.__escape_regex(email) + "\n")
		lck.close()

		self.log.write(1, "  __add_to_list(): \"%s\" added to %s" % (email, filenames[0]))

		return 0

	#-----------------------------------------------------------------------------
	def __remove_from_list(self, filenames, email=None):
		"""
		Removes the specified 'email' from the first filename in the array 
		'filenames'. Note that entries that would allow this list to match are 
		NOT removed, but instead the email passed is used as the regexp in the
		match. This is so to avoid removing more generic regexps added by
		the user.

		Note that unlike "add_to_list", email is a mandatory parameter
		(for security reasons).

		"""

		## Make sure it's not one of our own emails...
		if self.is_from_ourselves(email):
			self.log.write(1, "  __remove_from_list: \"%s\" is listed as one of our emails. It will not be removed from the list (%s)" % (email, filenames[0]))
			return -1

		self.log.write(10, "  __remove_from_list: filename=%s, email=%s" % (filenames[0], email))

		lck = asklock.AskLock()

		lockf = ""
		if self.config.rc_lockfile != "":
			lockf = self.config.rc_lockfile + "." + os.path.basename(filenames[0])

		lck.open(filenames[0], "r+", lockf)
		
		## We read the whole file in memory and re-write without
		## the passed email. Note that we expect the file to fit in memory.

		oldlist = lck.readlines()
		newlist = []

		## email must be alone on a line
		email = "^" + email + "$"
		
		for regex in listarray:
			if not re.match(regex, email, re.IGNORECASE):
				newlist.append(regex)
				
		lck.seek(0)
		lck.writelines(newlist)
		lck.close()

		return 0

	#------------------------------------------------------------------------------
	def invalid_sender(self):
		"""
		Performs some basic checking on the sender's email and return true if
		it seems to be invalid.
		"""

		sender_email = self.get_sender()[1]

		if (sender_email == '' or sender_email.find('@') == -1 or sender_email.find('|') != -1):
			self.log.write(1, "  invalid_sender(): Malformed 'From:' line (%s). " % sender_email)
			return 1
		else:
			return 0

	#------------------------------------------------------------------------------
	def is_mailing_list_message(self):
		"""
		We try to identify (using some common headers) whether this message comes
		from a mailing list or not. If it does, we return 1. Otherwise, return 0
		"""

		if (self.email_obj.__contains__("Mailing-List") or
			self.email_obj.__contains__("List-Id") or
			self.email_obj.__contains__("List-Help") or
			self.email_obj.__contains__("List-Post") or
			self.email_obj.__contains__("Return-Path") or
			( self.email_obj.__contains__("Precedence") and
				re.match("list|bulk", self.email_obj["Precedence"], re.IGNORECASE)
			) or
			( self.email_obj.__contains__("From") and
				re.match(".*(majordomo|listserv|listproc|netserv|owner|bounce|mmgr|autoanswer|request|noreply|nobody).*@", self.email_obj["From"], re.IGNORECASE)
			)
		):
			return 1
		else:
			return 0

	#------------------------------------------------------------------------------
	def __escape_regex(self, ist):
		"""
		Escapes dots and other meaningful characters in the regular expression.
		Returns the "escaped" string. This routine is pretty dumb meaning that
		it does not know how to handle an already escaped string. Use only in
		"raw", unescaped strings.
		"""

		evil_chars = "\\.^$*+|{}[]";

		for var in evil_chars:
			ist = ist.replace(var, "\\"+var)

		return(ist)

	#------------------------------------------------------------------------------
	def generate_auth(self):
		"""
		Generates an authentication string containing the current time and the
		MD5 sum of the current time + our rc5_key. This is normally sent out
		in every email generated by ASK in the X-ASK-Auth: email header.
		"""

		md5sum = hashlib.md5()

		## number of seconds since epoch as a string
		numsecs = "%d" % int(time.time())

		md5sum.update(numsecs.encode('utf-8'))					## Seconds and...
		md5sum.update(self.config.rc_md5_key.encode('utf-8'))	## md5 key...
	
		ascii_md5 = ''

		for ch in range(0,len(md5sum.digest())):
			ascii_md5 = ascii_md5 + "%02.2x" % md5sum.digest()[ch]
		
		self.log.write(5, "  generate_auth(): Authentication = %s-%s" % (numsecs, ascii_md5))

		return "%s-%s" % (numsecs, ascii_md5)

	#------------------------------------------------------------------------------
	def __get_auth_tokens(self, body = 0):
		"""
		Reads and parse the authorization string from the X-ASK-Auth SMTP header or
		from the email body, if the 'body' parameter is set to 1.  Normally, a tuple
		in the format (int(numsecs),md5sum) is returned. If the header does not exist
		or cannot be parsed, ("","") is returned.
		"""

		## Auth string may come from the body or from the headers

		authstring = None

		if body:
			self.email_obj.rewindbody()

			## Skip headers (until first blank line)
			while self.email_obj.fp.readline().strip():
				pass

			## Search for Auth Token
			while 1:
				buf = self.email_obj.fp.readline()
				if buf == '':
					break

				res = re.search("X-ASK-Auth: ([0-9]*)-([0-9a-f]*)", buf, re.IGNORECASE)

				if res:
					authstring = buf
					break
		else:
			authstring = self.email_obj.get("X-ASK-Auth")

		if not authstring:
			self.log.write(1, "  __get_auth_tokens(): No X-ASK-Auth SMTP header found")
			return ("","")

		self.log.write(5, "  __get_auth_tokens(): Authentication string = [%s]" % authstring)

		## Parse age and MD5
		res = re.search("([0-9]*)-([0-9a-f]*)", authstring, re.IGNORECASE)

		if not res:
			self.log.write(1, "  __get_auth_tokens(): Cannot parse X-ASK-Auth SMTP header")
			original_time = 0
			original_md5 = None
		else:
			original_time = int(res.group(1))
			original_md5  = res.group(2)

		return(int(original_time), original_md5)

	#------------------------------------------------------------------------------
	def validate_auth_md5(self, body = 0):
		"""
		Validates the MD5sum part of the X-ASK-Auth SMTP header. 
		Returns 1 if the authentication is valid, zero otherwise. If body = 1,
		the authentication token will be performed in the email's body as 
		opposed to the headers.
		"""

		(original_time, original_ascii_md5) = self.__get_auth_tokens(body = body)

		if not original_ascii_md5:
			self.log.write(1, "  validate_auth_md5(): Cannot read authorization tokens. Authentication Failed.")
			return 0

		## Check the md5sum (original_time + rc_md5_key)
		md5sum = hashlib.md5()
		md5sum.update(bytes("%s" % original_time, 'utf-8'))		## Seconds and...
		md5sum.update(bytes(self.config.rc_md5_key, 'utf-8'))	## md5 key...
	
		ascii_md5 = ''

		for ch in range(0,len(md5sum.digest())):
			ascii_md5 = ascii_md5 + "%02.2x" % md5sum.digest()[ch]
		
		## Compare
		if ascii_md5 == original_ascii_md5:
			self.log.write(1, "  validate_auth_md5(): Authentication succeeded")
			return 1
		else:
			self.log.write(1, "  validate_auth_md5(): MD5 tokens do not match (should be %s). Authentication failed" % ascii_md5)
			return 0

	#------------------------------------------------------------------------------
	def validate_auth_time(self, maxdays, body = 0):
		"""
		Validates the time part of the X-ASK-Auth SMTP header. 
		Returns 1 if the authentication is valid (newer than maxdays), 0 if not.
		if body == 1, the authentication will be performed in the email's
		body, as opposed to the headers.
		"""

		(original_time, original_ascii_md5) = self.__get_auth_tokens(body = body)

		if not original_ascii_md5:
			self.log.write(1, "  validate_auth_time(): Cannot read authorization tokens. Authentication Failed.")
			return 0

		## Check if original_time is older than 'maxdays' days.

		current_time = int(time.time())

		if (original_time >= (current_time - (maxdays * 86400))):
			self.log.write(1, "  validate_auth_time(): Time Authentication succeeded")
			return 1
		else:
			self.log.write(1, "  validate_auth_time(): Auth time is older than %d days. Authentication failed" % maxdays)
			return 0

	#------------------------------------------------------------------------------
	def summary(self, maxlen = 150):
		"""
		Returns a string containing a preview of the current message. HTML
		code will be stripped from the input. At most 'maxlen' bytes will
		be copied from the original mail.
		"""

		self.email_obj.rewindbody()

		content_boundary = ''

		## Skip to "boundary" if Content-type == multipart
		content_type     = self.email_obj["Content-Type"]

		res = re.search("boundary.*=.*\"(.*)\"", content_type, re.IGNORECASE)
		if not res:
			res = re.search("boundary.*=[ ]*(.*)[, ]*", content_type, re.IGNORECASE)

		if res:
			content_boundary = res.group(1)
			self.log.write(10, "  summary: content_boundary = %s" % content_boundary)

			# Skip to Content-Boundary, if any

			found = 0
			while 1:
				buf = self.email_obj.fp.readline()

				if buf == '':
					break

				if buf.find(content_boundary) != -1:
					found = 1
					break
			
			if found:
				## Skip until first blank line or EOF
				while 1:
					buf = self.email_obj.fp.readline().strip()
					if not buf:
						break
			else:
				## There is a content-type/boundary but we couldn't 
				## find one. Just rewind the message body to the start of it.
				self.email_obj.rewindbody()
					
		## We read the next 100 lines skipping "content-boundary" (if any)
		## and stopping at the end-of-file if found first.

		result  = ''
		buf   	= ''
		lines   = 100

		while lines > 0:
			buf = self.email_obj.fp.readline()
			if buf == '' or (content_boundary != '' and buf.find(content_boundary) != -1):
				break

			result = result + buf.strip() + " "

		result = self.strip_html(result)
		result = result.rstrip()
		result = result.lstrip()

		if len(result) > maxlen:
			result = result[0:maxlen] + "(...)"

		return result

	#------------------------------------------------------------------------------
	def __contains_string(self, regexp):
		"Returns line containing string if regexp matches any line in the current message"

		self.wrkf = open(self.tmpf_path, mode = 'rb')
		mail = self.wrkf.read()
		self.wrkf.close()

		try:
			if ( re.search( bytes(regexp, 'utf-8' ), mail, re.IGNORECASE) ):
				return True
		except:
			self.log.write(1,"  __contains_string(): WARNING: Invalid regular expression: \"%s\". Ignored." % regexp)

		return False

	#------------------------------------------------------------------------------
	def __save_to(self, dest):
		"""
		Saves the current message text into file 'dest'
		"""

		self.log.write(5, "  __save_to(): Copying to %s" % dest)

		self.wrkf = open(self.tmpf_path, mode = 'rb')
		fh_output = open(dest, mode = 'wb')
		fh_output.write( self.wrkf.read() )
		self.wrkf.close()
		fh_output.close()

	#------------------------------------------------------------------------------
	def match_recipient(self):
		"""
		This function will try to match the recipient of the message in the list
		of recipients contained in the rc_mymails array. If one is found, it is
		returned. Otherwise, it returns None.
		"""

		for (recipient_name, recipient_mail) in self.get_recipients():
			for our_address in self.config.rc_mymails:
				if recipient_mail.lower() == our_address:
					self.log.write(1, "  match_recipient(): Found a match with %s" % our_address)
					return our_address

		self.log.write(1, "  match_recipient(): No Match found.")

		return None
		
	#------------------------------------------------------------------------------
	def get_matching_recipient(self):
		"""
		This function will call "match_recipient" to determine whether the recipient
		of the current email is in our list of recipients. If so, the corresponding
		recipient will be returned. If not, an appropriate default will be chosen
		(usually the first email in the list rc_mymails).
		"""

		email = self.match_recipient()

		if not email:
			email = self.config.rc_mymails[0]

		self.log.write(1, "  get_matching_recipient(): Returning %s" % email)

		return email
		
	#------------------------------------------------------------------------------

	def strip_html(self, str):
		"""
		Strips all HTML from the input string and returns the stripped string.
		"""

		class HTMLStrip(html.parser.HTMLParser):
			def __init__(self):
				super(HTMLStrip, self).__init__()
				self.result = [ ]

			def handle_data(self, data):
				self.result.append(data)

			def get_text(self):
				return ''.join(self.result)

		try:
			s = HTMLStrip()
			s.feed(str)
			s.close()
		except html.parser.HTMLParseError:
			pass

		return s.gettext()

"""Converts HTML to plain text (stripping tags and converting entities).
>>> html_to_text('<a href="#">Demo<!--...--> <em>(&not; \u0394&#x03b7;&#956;&#x03CE;)</em></a>')
'Demo (\xac \u0394\u03b7\u03bc\u03ce)'
"Plain text" doesn't mean result can safely be used as-is in HTML.
>>> html_to_text('&lt;script&gt;alert("Hello");&lt;/script&gt;')
'<script>alert("Hello");</script>'
Always use html.escape to sanitize text before using in an HTML context!

HTMLParser will do its best to make sense of invalid HTML.
>>> html_to_text('x < y &lt z <!--b')
'x < y < z '

Unrecognized named entities are included as-is. '&apos;' is recognized,
despite being XML only.
>>> html_to_text('&nosuchentity; &apos; ')
"&nosuchentity; ' "
"""
#------------------------------------------------------------------------------

## EOF ##
