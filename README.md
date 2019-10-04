# Active-Spam-Filter
Active Spam Filter , ASK , adaptation to Python3

The original, programmed by Marco Paganini, had its last update in 2004. It was updated for Python 2.7 by Celer in 2012.
This version works with Python3, was tested using v 3.4, and some obsolete references to libraries were removed and replaced by newer ones (hashlib, email, html.parser, pathlib). Many of the file I/O actions were modified to binary mode to be able to process encodings like latin1 and utf-8.
In a basic sendmail/procmail installation the .procmailrc file of a particular system user will pipe the email to the 'askfilter' executable with information of the user's ASK home directory. In that latter directory one finds the user's .askrc configuration file.  
Example .procmailrc line:
:0 fW
|/usr/bin/askfilter --procmail --loglevel=1 --logfile=\<log path/\>ask.log --home=\<user path\>\<user name\>
  
a reference .askrc is given in the templates folder and needs a version for every email user in that user's ask directory.
See Marco Paganini's original instructions about the installation.
