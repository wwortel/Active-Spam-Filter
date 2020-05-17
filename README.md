# Active-Spam-Filter
Active Spam Filter , ASK , its adaptation to Python3.

The original, programmed by Marco Paganini, had its last update around 2006 and runs with early Python2. It was updated for Python 2.7 by Celer in 2012. It allows testing on various header fields and allows to define what should be delivered, what should be first confirmed by the sender, and what should be discarded.
This version has been reworked to work with Python3, and has been tested using v 3.4 and 3.7; some obsolete references to libraries were removed and replaced by newer ones (hashlib, email, html.parser, pathlib). Many of the file I/O actions were modified to binary mode to be able to process encodings like latin1 and utf-8 and to deal with the different string concept in Python3 vs. Python2. Only ASK's mode in which stdin and stdout are used as filter interfaces has been tested.
In priciple it should also work with mbox and mail directory modes but as said, that needs testing.
In a basic sendmail/procmail installation the .procmailrc file of a particular system user will pipe the email to the 'askfilter' executable with information of the user's home directory. In that latter directory one finds the user's .askrc configuration file.  
Example .procmailrc lines:

:0 fW

|/usr/bin/askfilter --procmail --loglevel=1 --logfile=\<log path/\>ask.log --home=\<user path/\>\<user name\>
  
a reference .askrc is given in the templates folder and needs a version for every email user in that user's home directory.
See Marco Paganini's original instructions about the installation.

General criticism against this type of 'confirm to my request to reply before an email from your address, new to me, will be delivered' is that it generates additional email traffic. Yet this is quite limited when ASK is used as the last filter after other means to block unsollicited email, like the firewall ( connect frequency and geographical origin), milter-regex, SPF, DKIM, and DMARC, have been applied.
In practice this cascaded arrangement pretty much cleans the inbox from any spam.

Keywords: spam, anti-spam, milter, email filter 

DONATIONS
---------

Donations are accepted:
- BTC: 1LkzWBvy847UNvAcJHjMJJbpHcNY8VnTL
Thank you!
