============
Options
============

Security Monkey's behavior can be adjusted with options passed using a configuration
file or directly using the command line. Some parameters are only available
in the configuration file.

If an option is not passed, Security Monkey will use the default value from the file
security_monkey/default-config.py.

You also have the option of providing environment aware configurations through the use
of the SECURITY_MONKEY_SETTINGS environmental variable.

Any variables set via this variable will override the default values specified in default-config.py


Config File
===========

LOG_LEVEL
---------

Standard python logging levels (ERROR, WARNING, DEBUG) depending on how much output you would like to see in your logs

LOG_FILE
--------

Where you would like Security Monkey's logs to be written to

R53
---

Specify if you want Security Monkey to create a DNS entry for itself and what DNS name you would like

FQDN
----

This is used for various redirection magic that to get the Security Monkey UI working nice with the API


SQLALCHEMY_DATABASE_URI
-----------------------

Specify where you would like Security Monkey to store it's results

SQLALCHEMY_POOL_SIZE & SQLALCHEMY_MAX_OVERFLOW
----------------------------------------------

Because of the parallel nature of Security Monkey we have to have the ability to tweak the number of concurrent connections we can make. The default values should be sufficient for <= 20 accounts. This may need to be increased if you are dealing with a greater number of accounts.

API_PORT
-------- 

Needed for CORS whitelisting -- this should match the port you have told Security Monkey to listen on. If you are using nginx it should match the port that nginx is listening on for the /api endpoint.

WEB_PORT
--------

Needed for CORS whitelisting -- this should match the port you have configured nginx to listen on for static content.

WEB_PATH
--------

USE_BROWSERID
-------------

Setting this to ``True`` will enable use of `Flask-Browserid <http://pythonhosted.org/Flask-BrowserID/>`_. This will cause Security Monkey to use `Persona <https://www.persona.org/>`_ (previously called Browserid) to authenticate users instead of using the password field in the local user table.

Additional Options
------------------

As Security Monkey uses Flask-Security for authentication see .. _Flask-Security: https://pythonhosted.org/Flask-Security/configuration.html for additional configuration options.

If you enable use of Flask-Browserid there will be additional configuration options available. See .. _Flask-Browserid: http://pythonhosted.org/Flask-BrowserID/#optional-configuration

Command line
==================

--host and --port
-------------------

The host and port on which to listen for incoming request. Usually 127.0.0.1
and 8000 to listen locally or 0.0.0.0 and 80 to listen from the outside.

Default: 127.0.0.1 and 8000

Setting file : HOST and PORT

--version and --help
--------------------

Display the help or the version of 0bin.

Default: None

Configuration file equivalent: None

