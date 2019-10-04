import os
import sys
import stat

#------------------------------------------------------------------------------
def read_config(configfile):
	"""
	Reads config file pointed to by 'configfile' and process the options 
	accordingly. Note that this function will expand lists and environment
	variables found inside the options.
	"""
	rc_msgdir      = configfile
	if not os.path.exists(rc_msgdir):
		os.mkdir(rc_msgdir)
	if not os.stat(rc_msgdir).st_mode == stat.S_IRWXU | stat.S_IRWXG :
		os.chmod(rc_msgdir, stat.S_IRWXU | stat.S_IRWXG )

read_config("/usr/share/asktest/queue")
