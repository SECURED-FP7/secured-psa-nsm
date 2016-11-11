# -*- Mode:Python;indent-tabs-mode:nil; -*-
#
#   File:       psaExceptions.py
#   Created:    05/09/2014
#   Author:     BSC
#
#   Description:
#       Custom execption class to manage error in the PSC
#

class psaExceptions( object ):

    class confRetrievalFailed( Exception ):
        pass
