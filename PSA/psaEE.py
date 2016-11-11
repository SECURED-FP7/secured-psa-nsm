# -*- Mode:Python;indent-tabs-mode:nil; -*-
#
# File: psaEE.py
# Created:    27/08/2014
# Author:     BSC
# Author:     jju / VTT Technical Research Centre of Finland Ltd., 2016
#
# Description:
#       Web service running on the PSA interacting with the PSC
#
#

import falcon
#import json
import Config
import logging
import subprocess
from execInterface import execInterface
from getConfiguration import getConfiguration
from psaExceptions import psaExceptions
from dumpLogFile import dumpLogFile
import os.path

conf = Config.Configuration()
date_format = "%m/%d/%Y %H:%M:%S"
log_format  = "[%(asctime)s.%(msecs)d] [%(module)s] %(message)s"

logging.basicConfig( filename = conf.LOG_FILE,
                     level    = logging.DEBUG,
                     format   = log_format,
                     datefmt  = date_format )

# Enforce logging level even if handlers had already
# been added into the root logger:
logger = logging.getLogger()
logger.setLevel( logging.DEBUG )

#pscAddr     = conf.PSC_ADDRESS
#configsPath = conf.PSA_CONFIG_PATH
#psaID       = conf.PSA_ID
#confID = conf.CONF_ID

if conf.TEST_MODE:
    logging.info( 'Test Mode enabled' )

logging.info( "--------" )
logging.info( "PSA EE init." )
logging.info( "PSA ID: " + str( conf.PSA_ID ) )
logging.info( "PSA NAME: " + str( conf.PSA_NAME ) )
logging.info( "PSA VERSION: " + str( conf.PSA_VERSION ) )
logging.info( "PSA-PSC API version: " + str( conf.PSA_API_VERSION ) )
logging.info( "PSA log location: " + str( conf.PSA_LOG_LOCATION ) )
logging.info( "--------" )

# instantiate class object to manage REST interface to the PSC
execIntf = execInterface( conf.PSA_HOME,
                          conf.PSA_CONFIG_PATH,
                          conf.PSA_SCRIPTS_PATH,
                          conf.PSA_LOG_LOCATION,
                          conf.PSA_ID,
                          conf.PSC_ADDRESS,
                          str(conf.PSA_API_VERSION))
#confHand = getConfiguration(pscAddr, configsPath, confID, psaID)
confHand = None
if not conf.TEST_MODE:
    confHand = getConfiguration( conf.PSC_ADDRESS,
                                 conf.PSA_CONFIG_PATH,
                                 conf.PSA_SCRIPTS_PATH,
                                 conf.PSA_ID,
                                 str(conf.PSA_API_VERSION) )

# start the HTTP falcon proxy and adds reachable resources as routes
app = falcon.API()
base = '/' + str( conf.PSA_API_VERSION ) + '/execInterface/'
app.add_route( base + '{command}',  execIntf )

dumpLog = dumpLogFile()
#FOR DEBUGGING ONLY, REMOVE IN PRODUCTION
app.add_route( base + 'dump-log-ctrl',  dumpLog )

logging.info("execInterface routes added.")

# Inform our PSC that we are up
#TODO
'''
try:
    start_res = confHand.send_start_event()
    # We don't need to enable anything
    #proc = subprocess.Popen(confScript, stdout=subprocess.PIPE, shell=True)
    #(out, err) = proc.communicate()
except psaExceptions as exc:
    pass
'''
# Pull configuration and start the PSA.
try:
    if not conf.TEST_MODE:
        confScript = confHand.pullPSAconf( execIntf )

    else: # Do local test setup

        # Check that some psaconf file exists
        if not os.path.isfile( conf.PSA_CONFIG_PATH + '/psaconf' ):
            raise psaExceptions.confRetrievalFailed()

        execIntf.callInitScript()

        if conf.TEST_MODE_IP != None:

            # Only run ip_conf.sh if all the parameters are present
            if ( conf.TEST_MODE_DNS == None
                 or conf.TEST_MODE_NETMASK == None
                 or conf.TEST_MODE_GATEWAY == None ):
                raise psaExceptions.confRetrievalFailed()

            logging.info( 'PSA requires IP, configuring...' )
            ip      = conf.TEST_MODE_IP
            dns     = conf.TEST_MODE_DNS
            netmask = conf.TEST_MODE_NETMASK
            gateway = conf.TEST_MODE_GATEWAY
            logging.info( 'ip: ' + str( ip ) )
            logging.info( 'gateway: ' + str( gateway ) )
            logging.info( 'dns: ' + str( dns ) )
            logging.info( 'netmask: ' + str( netmask ) )

            ret = subprocess.call( [ conf.PSA_SCRIPTS_PATH + 'ip_conf.sh',
                                     ip, gateway, dns, netmask ] )
            logging.info( 'Result of setting config: ' + str( ret ) )
        else:
            logging.info( "PSA doesn't require IP, skipping configuration." )
            logging.info('PSA '+ conf.PSA_ID + ' configuration registered' )

    execIntf.callStartScript()

except psaExceptions.confRetrievalFailed as e:
    print e

logging.info( "PSA start done." )

# http request to ask for the configuration and start the script
'''
try:
    confScript = confHand.pullPSAconf()
    proc = subprocess.Popen(confScript, stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
except psaExceptions as exc:
    pass
'''
