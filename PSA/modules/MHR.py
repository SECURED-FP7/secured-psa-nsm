# -*- Mode:Python;indent-tabs-mode:nil; -*-
#
# MHR.py
#
# Implements a malware detection module that communicates with MHR.bro
#
# Author: jju, jk / VTT Technical Research Centre of Finland Ltd., 2016
#

import logging

from broccoli import event, record_type, record
from modules.BroModule import BroModule
import modules.BroEventDispatcher as BroEventDispatcher

MHRConfigRecord = record_type( 'op',    # Operation type (add|reset)
                               'mime' ) # Mime to add

# Bro's response records:

# Alert event:
MHRRecord = record_type( 'id',       # Operation ID (match)
                         'ts',       # When the file was detected
                         'hash',     # Matchin sha1 hash
                         'fid',      # Bro's file ID
                         'name',     # Filename, if available
                         'service',  # Service (e.g., HTTP) using which the file
                                     # was loaded
                         'source',   # List of space separated addresses
                         'mime',     # Mime type of the file
                         'detected', # First time the malware was detected
                         'rate',     # Times the malware has been detected
                         'url',      # VirusTotal URL for the malware
                         'msg' )     # Message (not included in 'match')

# Log event:
MHRLogRecord = record_type( 'id',       # Operation ID (match)
                            'ts',       # When the file was detected
                            'hash',     # Matchin sha1 hash
                            'fid',      # Bro's file ID
                            'name',     # Filename, if available
                            'service',  # Service (e.g., HTTP) using which the
                                        # file was loaded
                            'source',   # List of space separated addresses
                            'mime',     # Mime type of the file
                            'msg' )     # Message (not included in 'match')

# Key for receiving Bro events.
MHRModuleKey = 'MHRModuleEvent'

class MHRModule( BroModule ):

    rules = { }

    def __init__( self, logger ):
        super( MHRModule, self ).__init__( 'MHR.bro', logger )
        BroEventDispatcher.register( MHRModuleKey, self )

    def onRule( self, rule ):

        # Current only checks uses mime-type condition:

        if 'mime-type' in rule.conditions:
            self.rules[ rule.ruleId ] = rule

            if self.state == BroModule.State.Started:
                self._sendRule( rule )

            return True

        return False

    def onStart( self, connection ):
        super( MHRModule, self ).onStart( connection )
        self.reset( False )
        self._sendAllRules()

    def onStop( self ):
        super( MHRModule, self ).onStop()

    def _sendRule( self, rule ):
        """
         Send a single rule to bro module
        """
        mimes = rule.conditions[ 'mime-type' ]
        for mime in mimes:
            try:
                rec      = record( MHRConfigRecord )
                rec.op   = 'add'
                rec.mime = str( mime )
                logging.info( 'Passing rule to Bro: ' + rule.ruleId
                              + ' (' + mime + ')' )
                self.connection.send( 'on_mhr_config', rec )
            except Exception:
                logging.warning( 'Config exception for rule: ' + rule.ruleId )

    def _sendAllRules( self ):
        for key, rule in self.rules.iteritems():
            self._sendRule( rule )

    def reset( self, resetRules = True ):
        # Only send rules if connected to Bro
        if self.state == BroModule.State.Started:
            try:
                rec      = record( MHRConfigRecord )
                rec.op   = 'reset'
                rec.mime = 'reset'
                logging.info( 'Passing rule to Bro: reset' )
                self.connection.send( 'on_mhr_config', rec )
            except Exception:
                logging.warning( 'Config exception for rule: reset' )

        if resetRules:
            self.rules = { }

    def _log_alert( self, rule, data ):

        try:
            fmt = "[%s] Rule '%s'(HSPL: %s) fired on file %s (%s, %s) from %s (%s): %s\n"

            text = ''
            if not data.msg or data.msg == None or data.msg == '' :
                text = data.url
            else:
                text = data.msg + ' (local hash)'

            line = fmt % ( data.ts,
                           rule.ruleId,
                           rule.hspl[ 'id' ],
                           data.fid,
                           data.mime,
                           data.hash,
                           data.source,
                           data.service,
                           text )
            # Log and alert
            self.logger.onEvent( line )

            fmt2 = "File (%s, %s) from %s (%s): %s"
            info = fmt2 % ( data.mime,
                           data.hash,
                           data.source,
                           data.service,
                           text )
            self.logger.onNotifyEvent( rule.hspl['text'], 'Detected malicious file!', info )
        except Exception as e:
            logging.error( e )

    def _log_event( self, data ):

        try:
            fmt = "[%s] Info: file %s (%s, %s) from %s (%s): %s\n"
            line = fmt % ( data.ts,
                           data.fid,
                           data.mime,
                           data.hash,
                           data.source,
                           data.service,
                           data.msg  )

            self.logger.onEvent( line )
        except Exception as e:
            logging.error( e )


    def onEvent( self, data ):
        logging.error( 'Event ' + data.id )

        if data.id == 'match':
            count = 0
            for key, rule in self.rules.iteritems():
                if data.mime in rule.conditions[ 'mime-type' ]:
                    count += 1
                    self._log_alert( rule, data )
                    # Make sure that a log entry is generated even if
                    # mime matching in Bro and Python aren't equivalent:
            if count == 0:
                self._log_alert( '?', data )

        elif data.id == 'log':
            self._log_event( data )

# Dispatching events:
@event(MHRRecord)
def mhr_alert( data ):
    BroEventDispatcher.dispatch( MHRModuleKey, data )

# Dispatching events:
@event(MHRLogRecord)
def mhr_log( data ):
    BroEventDispatcher.dispatch( MHRModuleKey, data )

# Required for module loading:
module = MHRModule
