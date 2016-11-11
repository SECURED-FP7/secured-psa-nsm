# -*- Mode:Python;indent-tabs-mode:nil; -*-
#
# BroManager.py
#
# An interface to Bro.
#
# Author: jounih / VTT Technical Research Centre of Finland Ltd., 2015
#         jju    / VTT Technical Research Centre of Finland Ltd., 2016
#

import threading
import subprocess
import os
import os.path
import logging

# In the new image, the broccoli location is here
import sys
sys.path.append( '/opt/bro/lib/broctl/' )

from broccoli import Connection
import ConfigLoader
import ModuleLoader

# A simple Thread-object that is used to call Broccoli's
# processInput() every now and then to keep Bro event
# handling running.

class InputThread( threading.Thread ):

    polling         = None # threading.Event instance for waiting
    pollingInterval = 1    # Polling interval in seconds
    connection      = None # Bro connection to poll

    def __init__( self, connection ):
        self.connection = connection
        threading.Thread.__init__( self )
        self.polling = threading.Event()

    def run( self ):
        while ( ( not self.polling.is_set() )
                and self.connection != None ):
            self.connection.processInput()
            self.polling.wait( self.pollingInterval )

# Exception class for Bro related exceptions.
class BroException( Exception ):
    def __init__( self, value ):
        super( BroException, self ).__init__( value )
        self.value = value

    def __str__( self ):
        return repr( self.value )

# BroManager is *the* interface to Bro
#
# Allows starting and stopping Bro and loading new modules
#
# State management:
#  BroManager controls an instance of the Bro network monitor. To keep
#  state management simple there are essentially two states: 'running'
#  and 'stopped'. All changes (e.g. loading modules, adding rules) should
#  be made while Bro is stopped.
#

class BroManager( object ):
    # TODO: These should be configurable:
    configFile      = '/opt/bro/share/bro/site/secured.bro'
    broctlPath      = '/opt/bro/bin/broctl'

    SCRIPT_PRE_INIT  = 'pre-init.bro'
    SCRIPT_POST_INIT = 'post-init.bro'

    # Bro PSA installation base directory. All directiories are relative to this
    baseDir         = None
    # Module directory: self.baseDir + '/modules'
    moduleDir       = None
    # Current Inputhread object. None if there is not connection.
    thread          = None
    # Bro Connectio object instance if Bro manager is currently connected to
    # one, None otherwise.
    connection      = None
    # Dictionary of currently loaded Bro modules.
    modules         = { } # { "name": BroModule }
    # A logger to which Bro modules report their logs.
    # TODO: this is a quick hack: a better aproach should be implemented.
    logger          = None

    def __init__( self, base=None, logger=None ):
        if not os.getuid() == 0:
            raise Exception( 'BroManager requires root access!' )

        self.logger = logger
        if base != None:
            self.baseDir = base
        else:
            self.baseDir   = '/home/psa/pythonScript/'
        self.moduleDir = self.baseDir + '/modules'
        ModuleLoader.init( self.baseDir + '/modules.json' )

    def __del__( self ):
        self.disconnect()

    def isConnected( self ):
        return ( self.connection != None )

    # NOTE: it could be a good idea to use connect / disconnect internally
    # only and always use startBro / stopBro / loadConfig externally. However,
    # now connect() is also use to connect (or check) if a bro instance is
    # already running.

    def connect( self ): # throws IOError
        """
        Connect to a running Bro instance.

        Creates a thread that starts calling Broccoli's processInput()
        periodically.
        """
        if self.connection != None:
            self.disconnect()

        # Note: all Bro modules must be loaded *BEFORE* the Bro Connection
        # is created. The reason for this is that Broccoli Python interface
        # only registers event handlers for those @events that it has seen
        # the moment when the Connection is created. Thus, loading new modules
        # requires creating a new Connection.

        # TODO: make the address configurable

        self.connection = Connection( "127.0.0.1:47760", connect = False )

        try:
            self.connection.connect()
        except IOError as e:
            self.connection = None
            raise e

        self.thread = InputThread( self.connection )
        self.thread.start()

    def disconnect( self ):
        """
        Close the connection with the Bro instance.

        Stops the thread polling Broccoli's processInput()
        """
        if self.thread != None:
            if self.thread.polling:
                self.thread.polling.set()
            self.thread.connection = None
            self.thread.join()
            self.thread = None
        if self.connection != None:
            self.connection.connDelete()
            self.connection = None

    def _loadModule( self, name ):
        """
        Loads a module corresponding to 'name' if one is
        found in the modules.json file.
        """
        module = ModuleLoader.load( name )
        if module == None:
            logging.error( 'Could not load module: ' + name)
            return None

        # Create an instance of the module
        instance = module( self.logger )
        self.modules[ name ] = instance
        logging.info( 'Module loading succesfull: ' + name)
        return instance

    def _getOrLoadModule( self, key ):
        """
        Return a module corresponding to 'key'. If one is not present
        try to load it based on the modules.json file.
        """
        try:
            return self.modules[ key ]
        except KeyError:
            return self._loadModule( key )

    def loadConfig( self, filename ):
        """
        Loads a configuration file. Before loading, each module is disabled.
        Configuration rules are passed to corresponding modules. In case such
        module has not been loaded, they are loaded according to modules.json
        file.

        Note: this function should only be called when Bro is stopped!
        """

        # This function used to reset each module, but requiring Bro to
        # be stopped makes more sense and keeps the state management
        # easier.
        if self.connection != None:
            raise BroException( 'Invalid state' )

        self._disablePreInitScript()
        self._disableAllModules()
        self._disablePostInitScript()

        self.modules = { }
        rules = ConfigLoader.load( filename )

        self._broctl_cmd( 'cleanup', 'all' )

        logging.info( 'Enabling pre-init script' )
        self._enablePreInitScript()

        for rule in rules:
            module = self._getOrLoadModule( rule.operation )
            if module == None:
                logging.warning( 'No module for operation '
                                 + rule.operation
                                 + ' (' + rule.ruleId + ')' )
                continue

            if not module.enabled:
                self._enableModule( module )

            logging.info( 'Setting rule %s for module %s'
                          % ( rule.ruleId, module.broScript ) )
            if not module.onRule( rule ):
                logging.warning( 'Invalid rule: ' + rule.ruleId )

        logging.info( 'Enabling post-init script' )
        self._enablePostInitScript()

        # Note: broctl install must be run when ever the local policy scripts
        # are modified. This means each time a module is enabled or disabled.
        # However, it is not a good idea to run them in enable/disableModule
        # functions separately for each change.

        self._broctl_cmd( 'check' )
        self._broctl_cmd( 'install' )

        # The 'broctl update' command is only needed if Bro is already running.
        # However, update won't update all Bro state, so stopping and restarting
        # Bro for any updates is a safer way. We don't expect this to happen
        # often!

        #        self._broctl_cmd( 'update' )


    def startBro( self ):
        """
        Starts bro instance and calls each modules onStart-callback.
        """

        if self.connection != None:
            raise BroException( 'Invalid state' )

        logging.info( 'Starting Bro' )
        # Newer Bro versions have commend 'deploy', which must be
        # run when ever the scripts are modified. It should be equivalent
        # of 'check', 'install' and 'restart'
        self._broctl_cmd( 'cleanup', '--all' )
        self._broctl_cmd( 'check' )
        self._broctl_cmd( 'install' )
        #self._broctl_cmd( 'update' )
        self._broctl_cmd( 'start' )
        self.connect()

        logging.info( 'Starting modules' )
        for key, module in self.modules.iteritems():
            if module.enabled:
                logging.info( 'Module: ' + module.broScript )
                module.onStart( self.connection )
        logging.info( 'Done' )
        logging.info( 'Bro Started' )

    def stopBro( self ):
        """
        Stops running bro instance. Each module's onStop-callback is called
        before bro is stopped to allow any cleanup actions necessary.
        """

        if self.connection == None:
            raise BroException( 'Invalid state' )

        logging.info( 'Stopping Bro' )
        logging.info( 'Stopping modules' )
        for key, module in self.modules.iteritems():
            if module.enabled:
                logging.info( 'Module: ' + module.broScript )
                module.onStop()
        logging.info( 'Done' )

        self.disconnect()
        self._broctl_cmd( 'stop' )
        logging.info( 'Bro Stopped' )

    def restartBro( self ):
        self.stopBro()
        self.startBro()

    def _broctl_cmd( self, cmd, *args ):
        """
        Execute a command using broctl
        """
        cArgs = [ self.broctlPath, cmd ]
        for arg in args:
            cArgs.append( arg )

        logging.info( 'Calling broctl: ' + str( cArgs ) )
        # will wait for completion of cmd
        rv = subprocess.call( cArgs )
        if rv == 1:
            raise Exception( 'Error: broctl ' + cmd + ' failed!' )

    def _enableModule( self, module ):
        """
        Enables a specific Bro module.

        If the module is not listed in the Bro configuration file, it is added
        there. If the module is listed in the file, but commented out, the
        comment character is removed.

        Note: does not call module's onStart callback!
        Note: Bro must be restarted in order of these changes to take effect.
        """
        # See if the module name already exists in the configuration file:
        path = self.moduleDir + '/' + module.broScript
        rv = subprocess.call( [ 'grep',
                                '--quiet',
                                '@load ' + path,
                                self.configFile ] )
        if rv != 0: # No match found: add a new line
            with open( self.configFile, 'a' ) as f:
                f.write( '\n@load ' + path + '\n' )
            rv = 0
        else: # Remove comment chracater before the load directive
            pattern  = 's|^#*@load ' + path + '|@load ' + path + '|g'
            rv = subprocess.call( [ 'sed',
                                    '-i.bak',
                                    '--silent',
                                    pattern,
                                    self.configFile ] )

        if rv == 0:
            module.enabled = True
        return rv

    def _disableModule( self, module ):
        """
        Disable a specific Bro module.

        Essentially comments out the module from Bro configuration file.

        Note: does not call module's onStop callback!
        Note: Bro must be restarted in order of these changes to take effect.
        """
        # Comment the load directive out
        pattern  = 's|^@load ' + self.moduleDir + '/' + module.broScript
        pattern += '|#@load ' + self.moduleDir + '/' + module.broScript + '|g'
        rv = subprocess.call( [ 'sed',
                                '-i.bak',
                                '--silent',
                                pattern,
                                self.configFile ] )

        if rv == 0:
            module.enabled = False
        return rv

    def _disableAllModules( self ):
        """
        Disables all Bro modules.

        Essentially comments out all modules in the module directory from the
        Bro configuration file. This includes modules that are not listed in
        the current module configuration. The main purpose of this function is
        to ensure clean restart of Bro.

        Does not affect the currently loaded modules in any way.

        Note: Bro must be restarted in order of these changes to take effect.
        """

        # Comment the load directive out in order to disable the module
        pattern  = 's|^@load ' + self.moduleDir + '/'
        pattern += '|#@load ' + self.moduleDir + '/|g'
        rv = subprocess.call( [ 'sed',
                                '-i.bak',
                                '--silent',
                                pattern,
                                self.configFile ] )
        return ( rv == 0 )

    def _enablePreInitScript( self ):
        script = self.moduleDir + '/' + self.SCRIPT_PRE_INIT
        line = '@load ' + script
        # Remove the all instances of the line first to make sure that
        # the line is included only once and that its the first line!
        # This might usually not be needed, but let's make it anyways
        # to be sure that we don't have any unexpected side effects!
        _fileRemoveLines( self.configFile, line )
        _fileRemoveEmptyLines( self.configFile )
        # Only add the line if the pre-init script actually exists
        if _fileExists( script ):
            _filePrependLine( self.configFile, line )
        _fileRemoveEmptyLines( self.configFile )

    def _enablePostInitScript( self ):
        script = self.moduleDir + '/' + self.SCRIPT_POST_INIT
        line = '@load ' + script
        # Remove the all instances of the line first to make sure that
        # the line is included only once and that its the last line!
        # This might usually not be needed, but let's make it anyways
        # to be sure that we don't have any unexpected side effects!
        _fileRemoveLines( self.configFile, line )
        _fileRemoveEmptyLines( self.configFile )
        # Only add the line if the post-init script actually exists
        if _fileExists( script ):
             _fileAppendLine( self.configFile, line )
        _fileRemoveEmptyLines( self.configFile )

    def _disablePreInitScript( self ):
        script = self.moduleDir + '/' + self.SCRIPT_PRE_INIT
        line = '@load ' + script
        _fileRemoveLines( self.configFile, line )
        _fileRemoveEmptyLines( self.configFile )

    def _disablePostInitScript( self ):
        script = self.moduleDir + '/' + self.SCRIPT_POST_INIT
        line = '@load ' + script
        _fileRemoveLines( self.configFile, line )
        _fileRemoveEmptyLines( self.configFile )

# The file handling scripts below use mostly sed magic to do their things.
# This might not be the best or most pythonianic way to do the operations,
# but as most of the file-related functions above also make it this way
# let's continue the habbit...

def _fileExists( f ):
    return os.path.isfile( f )

def _fileContainsLine( f, line ):
    return ( subprocess.call( [ 'grep', '--quiet', 'line', f ] ) != 0 )

def _fileRemoveLines( f, line ):
    pattern  = 's|^' + line + '||g'
    rv = subprocess.call( [ 'sed', '-i.bak', pattern, f ] )
    return rv

def _fileRemoveEmptyLines( f ):
    rv = subprocess.call( [ 'sed', '-i.bak', '/^\s*$/d', f ] )
    return rv

def _filePrependLine( f, line ):
    # Sed magic doesn't work for empty files
    # However, in that case we only need to append
    if os.stat( f ).st_size == 0:
        _fileAppendLine( f, line )
    else:
        pattern  = '1s|^|' + line + '\\n|g'
        subprocess.call( [ 'sed', '-i.bak', '--silent', pattern, f ] )

def _fileAppendLine( f, line ):
    with open( f, 'a') as fi:
        fi.write( '\n' + line + '\n' )
