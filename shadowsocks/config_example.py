# !!! Please rename config_example.py as config.py BEFORE editing it !!!

import logging
# !!! Only edit this line when you update your configuration file !!!
# After you update, the values of CONFIG_VERSION in config.py and
# config_example.py should be the same in order to start the server
CONFIG_VERSION = '20160623-2'


# Manyuser Interface Settings
# ---------------------------
# Database Config
# `mysql` or `postgresql`
DB_TYPE = 'mysql'
DB_HOST = 'mengsky.net'
DB_PORT = 3306
DB_USER = 'root'
DB_PASS = 'root'
DB_NAME = 'shadowsocks'
# USUALLY this variable do not need to be changed
DB_USER_TABLE = 'users'
DB_TIMEOUT = 30

# Time interval between 2 pulls from the database
CHECKTIME = 30
# Time interval between 2 pushes to the database
SYNCTIME = 120
# Choose True if you want to use custom method and False if you don't
CUSTOM_METHOD = True


# Manager Settings
# ----------------
# USUALLY you can just keep this section unchanged
# It is not necessary to change the password if you only listen on 127.0.0.1
MANAGE_PASS = 'passwd'
# if you want manage in other server you should set this value to global ip
MANAGE_BIND_IP = '127.0.0.1'
# make sure this port is idle
MANAGE_PORT = 65000


# Network Settings
# ----------------
# Address binding settings
# if you want to bind ipv4 and ipv6 please use '::'
# if you want to bind only all of ipv4 please use '0.0.0.0'
# if you want to bind a specific IP you may use something like '4.4.4.4'
SS_BIND_IP = '::'
# This default method will be replaced by database record if applicable
SS_METHOD = 'aes-256-cfb'
# Choose whether enforce Shadowsocks One Time Auth (OTA)
# OTA will still be enabled for the client if it sends an AUTH Address type(0x10)
SS_OTA = False
# Skip listening these ports
SS_SKIP_PORTS = [80]
# TCP Fastopen (Some OS may not support this, Eg.: Windows)
SS_FASTOPEN = False
# Shadowsocks Time Out
# It should > 180s as some protocol has keep-alive packet of 3 min, Eg.: bt
SS_TIMEOUT = 185


# Firewall Settings
# -----------------
# These settings are to prevent user from abusing your service
SS_FIREWALL_ENABLED = True
# Mode = whitelist or blacklist
SS_FIREWALL_MODE = 'blacklist'
# Member ports should be INTEGERS
# Only Ban these target ports (for blacklist mode)
SS_BAN_PORTS = [22, 23, 25]
# Only Allow these target ports (for whitelist mode)
SS_ALLOW_PORTS = [53, 80, 443, 8080, 8081]
# Trusted users (all target ports will be not be blocked for these users)
SS_FIREWALL_TRUSTED = [443]
# Banned Target IP List
SS_FORBIDDEN_IP = []


# Logging and Debugging Settings
# --------------------------
LOG_ENABLE = True
SS_VERBOSE = False
# Available Log Level: logging.NOTSET|DEBUG|INFO|WARNING|ERROR|CRITICAL
LOG_LEVEL = logging.INFO
LOG_FILE = 'shadowsocks.log'
# The following format is the one suggested for debugging
# LOG_FORMAT = '%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s'
LOG_FORMAT = '%(asctime)s %(levelname)s %(message)s'
LOG_DATE_FORMAT = '%b %d %H:%M:%S'
