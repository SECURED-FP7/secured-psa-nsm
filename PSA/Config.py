# -*- Mode:Python;indent-tabs-mode:nil; -*-
#
# Config.py
#
# PSA configuration file parsing
#
# Author: anon,
#         jju / VTT Technical Research Centre of Finland Ltd., 2016
#

import ConfigParser
import os
#import copy
import logging

def resolve_psa_home():
    try:
        home = os.environ[ 'PSA_HOME' ]
        if not os.path.isdir( home ):
            error = 'Environment variable $PSA_HOME is not a valid directory'
            raise RuntimeError( error )
        if not os.path.isabs( home ):
            error ='Environment variable $PSA_HOME path is not absolute'
            raise RuntimeError( error )
        return home
    except KeyError:
        logging.warning( 'Environment variable $PSA_HOME not set' )
    logging.info( 'Using current working directory as $PSA_HOME' )
    return os.getcwd()

def normalize_path( base, path ):
    return os.path.join( base, path)

def getboolean_default( config, section, option, default ):
    try:
        return config.getboolean( section, option )
    except ConfigParser.NoOptionError as e:
        return default

def get_default( config, section, option, default ):
    try:
        return config.get( section, option )
    except ConfigParser.NoOptionError as e:
        return default

class Configuration( object ):
    _instance = None # Singleton

    def __new__( cls, *args, **kwargs ):
        if not cls._instance:
            cls._instance = super( Configuration, cls ).__new__( cls, *args, **kwargs )
        return cls._instance

    def __init__( self ):
        config = ConfigParser.RawConfigParser()
        #config.read( 'psa.conf' )
        config.read( 'psaEE.conf' )

        # Hard-coded options
        self._PSA_HOME = resolve_psa_home()
        self._LOG_FILE = 'PSA.log'



        # Optional
        self._VERBOSE   = getboolean_default( config, 'configuration',
                                              'verbose', False )
        self._DEBUG     = getboolean_default( config, 'configuration',
                                              'debug', False )
        self._TEST_MODE = getboolean_default( config, 'configuration',
                                              'test_mode', False )

        self._TEST_MODE_IP      = get_default( config, 'configuration',
                                               'test_mode_ip', None )
        self._TEST_MODE_DNS     = get_default( config, 'configuration',
                                               'test_mode_dns', None )
        self._TEST_MODE_NETMASK = get_default( config, 'configuration',
                                               'test_mode_netmask', None )
        self._TEST_MODE_GATEWAY = get_default( config, 'configuration',
                                               'test_mode_gateway', None )

        # Required options:
        self._PSC_ADDRESS      = config.get( 'configuration', 'psc_address' )
        self._PSA_CONFIG_PATH  = config.get( 'configuration', 'psa_config_path' )
        self._PSA_ID           = config.get( 'configuration', 'psa_id' )
        self._PSA_SCRIPTS_PATH = config.get( 'configuration', 'scripts_path' )
        self._PSA_API_VERSION  = config.get( 'configuration', 'psa_api_version' )
        self._PSA_VERSION      = config.get( 'configuration', 'psa_version' )
        self._PSA_NAME         = config.get( 'configuration', 'psa_name' )
        self._PSA_LOG_LOCATION = config.get( 'configuration', 'psa_log_location' )

        # Make all relative paths absolute based on $PSA_HOME
        base = self._PSA_HOME
        self._LOG_FILE         = normalize_path( base, self._LOG_FILE )
        self._PSA_CONFIG_PATH  = normalize_path( base, self._PSA_CONFIG_PATH )
        self._PSA_SCRIPTS_PATH = normalize_path( base, self._PSA_SCRIPTS_PATH )
        self._PSA_LOG_LOCATION = normalize_path( base, self._PSA_LOG_LOCATION )

        self._CONF_ID = config.get( 'configuration', 'conf_id' )

    @property
    def PSA_HOME( self ):
        return self._PSA_HOME

    @property
    def TEST_MODE( self ):
        return self._TEST_MODE

    @property
    def TEST_MODE_IP( self ):
        return self._TEST_MODE_IP

    @property
    def TEST_MODE_DNS( self ):
        return self._TEST_MODE_DNS

    @property
    def TEST_MODE_NETMASK( self ):
        return self._TEST_MODE_NETMASK

    @property
    def TEST_MODE_GATEWAY( self ):
        return self._TEST_MODE_GATEWAY

    @property
    def LOG_FILE( self ):
        return self._LOG_FILE

    @property
    def VERBOSE( self ):
        return self._VERBOSE

    @property
    def PSC_ADDRESS( self ):
        return self._PSC_ADDRESS

    @property
    def PSA_CONFIG_PATH( self ):
        return self._PSA_CONFIG_PATH

    @property
    def PSA_SCRIPTS_PATH( self ):
        return self._PSA_SCRIPTS_PATH

    @property
    def PSA_ID( self ):
        return self._PSA_ID

    @property
    def PSA_NAME( self ):
        return self._PSA_NAME

    @property
    def PSA_API_VERSION( self ):
        return self._PSA_API_VERSION

    @property
    def PSA_VERSION( self ):
        return self._PSA_VERSION

    @property
    def PSA_LOG_LOCATION( self ):
        return self._PSA_LOG_LOCATION

    # @property
    # def CONF_ID(self):
    #     return self._CONF_ID
