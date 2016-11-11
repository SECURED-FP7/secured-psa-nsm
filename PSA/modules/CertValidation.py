
# -*- Mode:Python;indent-tabs-mode:nil; -*-
#
# CertValidation.py
#
# Implements a certificate chain verification module that utilises
# validate-certs.bro
#

import logging

from broccoli import event, record_type, record
from modules.BroModule import BroModule

# Log event:
CVLogRecord = record_type( 'id',       # Operation ID
                           'ts',       # When the cert was detected
                           'hashes',   # Cert hashes
                           'name',     # Cert subject
                           'msg' )     # Message (Trusted/expired/etc)

# Key for receiving Bro events.
CVModuleKey = 'CVModuleEvent'


class CVModule( BroModule ):

    def __init__( self, logger ):
        super( CVModule, self ).__init__( 'CertValidation.bro', logger )
        logging.info( 'CVModule init' );

    def onStart( self, connection ):
        super( CVModule, self ).onStart( connection )

    def onStop( self ):
        super( CVModule, self ).onStop()

    def onRule( self, rule ):
        logging.info( 'Rule received' );

    def _sendRule( ):
        logging.info( 'Passing rule to bro' );

    def _log_event( self, data ):

        try:
            fmt = "[%s] %s (%s: %s): %s\n"
            line = fmt % ( data.ts,
                           data.id,
                           data.name,
                           data.hashes,
                           data.msg  )

            self.logger.onEvent( line )
        except Exception as e:
            logging.error( e )

# Dispatching events:
@event(CVLogRecord)
def cv_log( data ):
    logging.info( "Event: Certificate validated" )    
    BroEventDispatcher.dispatch( CVModuleKey, data )


module = CVModule
