# -*- Mode:Python;indent-tabs-mode:nil; -*-
#
# BroModule.py
#
# A parent interface for all Bro modules.
#
# Each Bro module should define the functions declared in the
# BroModule class. Futhremore, each module must define module
# variable 'module' that contains the BroModule class defined
# in the module. The module variable is used by the BroManager
# to instantiate the module object.
#
# Any Bro event handlers (@event) should be registered to
# BroEventDispacther. This dispatcher is used to circument the fact
# that Broccoli Python interface expects the event handler to be
# a module function (not a class memeber).
#
# Author: jju / VTT Technical Research Centre of Finland Ltd., 2016
#


# NOTE: any communication with Bro should only happen if Bro
# is running, i.e., the module is in state 'Started'! Otherwise
# Gunicorn worker will boot unexpectably.

class BroModule( object ):

    class State( object ):
        Started, Stopped = range( 2 )

    broScript  = None          # Bro scrip's filename
    enabled    = False         # If the module is enabled currently
    connection = None          # Bro connection for sending events
    state      = State.Stopped # Modules current state
    logger     = None          # Logger to send log events to

    def __init__( self, filename, logger ):
        self.broScript = filename
        self.logger = logger

    def onRule( self, rule ):
        """
        Add a single configuration rule to module
        """
        return False

    def onStart( self, connection ):
        """
        Called when Bro is started.

        Bro is already running when this callback is called. The callback
        should be used to pass rule information to modules .bro script.
        """
        self.connection = connection
        self.state = self.State.Started

    def onStop( self ):
        """
        Called when Bro is being stopped.

        This callback should be used to perform any cleanup actions necessary.
        """

        self.state = self.State.Stopped

    def onEvent( self, event ):
        """
        Called if a Bro event is dispatched to this module.
        """
        pass

# Example module variable definition:
#module = BroModule
