# -*- Mode:Python;indent-tabs-mode:nil; -*-
#
# BroLoader.py
#
# A dummy module that loads config.bro file
#
# The rule for this module should be the las one in the list!
#
# Author: jju / VTT Technical Research Centre of Finland Ltd., 2016
#

from modules.BroModule import BroModule

class BroLoaderModule( BroModule ):

    rules    = { }

    def __init__( self, logger ):
        super( BroLoaderModule, self ).__init__( 'config.bro', logger )

    def onStart( self, connection ):
        super( BroLoaderModule, self ).onStart( connection )

    def onStop( self ):
        super( BroLoaderModule, self ).onStop()

    def onRule( self, rule ):
        return True

    def onEvent( self, data ):
        pass

module = BroLoaderModule
