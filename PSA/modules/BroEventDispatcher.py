# -*- Mode:Python;indent-tabs-mode:nil; -*-
#
# BroEventDispatcher.py
#
# A simple event dispatcher.
#
# Author: jju / VTT Technical Research Centre of Finland Ltd., 2016
#

import logging

callbacks = { }

def init():
    pass

def register( key, obj ):
    """
    Register a callback for key 'key'
    """
    global callbacks
    callbacks[ key ] = obj

def unregister( key ):
    """
    Unregisters callback for key 'key'
    """
    global callbacks
    del callbacks[ key ]

def dispatch( key, data ):
    """
    Dispatch event 'data' to the callback registered for key 'key'
    """
    global callbacks
    try:
        cb = callbacks[ key ]
        if cb != None:
            cb.onEvent( data )
    except Exception as e:
        logging.warning( 'No dispatcher for key: ' + key + ': ' + str( e ) )
