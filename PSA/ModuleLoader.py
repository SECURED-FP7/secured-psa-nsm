# -*- Mode:Python;indent-tabs-mode:nil; -*-
#
# ModuleLoader.py
#
# Loads python modules.
#
# Author: jju / VTT Technical Research Centre of Finland Ltd., 2016
#

import os
import json
import logging

# Modules filename
moduleFile = None

def init( filename ):
    global moduleFile
    moduleFile = filename

def _loadModule( path ):
    """
    First converts 'path' from file path representation to
    Python module name, i.e., removes file extension, converts
    slashes to dots, and removes . or .. from the start of the
    path if any (thus, paths will be relative to this directory).
    """
    path = path.strip()
    path = os.path.normpath( path )
    if path.endswith( '.py' ):
        path = path[:-3]
    changed = True
    while changed:
        changed = False
        while path.startswith( '.' ):
            path = path[1:]
            changed = True
        while path.startswith( '/' ):
            path = path[1:]
            changed = True
    name = path.replace( '/', '.' )
    logging.info( 'Loading: ' + name )
    module = __import__( name, fromlist=[ '' ] )
    return getattr( module, 'module' )


def load( name ):
    """
    Loads a module by name 'name' if one is listed in the
    modules file. Returns content of the variable called 'module'
    which should contain the module class declaration. If anything
    goes wrong, None is returned.
    """
    logging.info( 'Searching module: ' + moduleFile )
    try:
        with open( moduleFile, 'r' ) as config:
            data = json.load( config )
            modules = data[ 'modules' ]
            for module in modules:
                moduleName = module[ 'name' ]
                logging.info( 'Scanning: ' + moduleName )
                if moduleName == name:
                    logging.info( 'Found module: ' + name
                                  + ' (' + module[ 'module' ] + ')' )
                    return  _loadModule( module[ 'module' ] )
    except Exception as e:
        logging.warning( 'Module loading failed: ' + str( e ) )

    return None
