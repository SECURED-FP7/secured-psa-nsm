# -*- Mode:Python;indent-tabs-mode:nil; -*-
#
# ConfigLoader.py
#
# Loads a JSON configuration file and performs some sanity checks.
#
# Author: jju / VTT Technical Research Centre of Finland Ltd., 2016
#

import json

class ParseError( Exception ):
    def __init__( self,  value ):
        super( ParseError, self ).__init__( value )
        self.value = value

    def __str__ ( self ):
        return repr( self.value )

class ObjectEnum( object ):
    Connection, Port, Address = range( 3 )

def parseObjectEnum( value ):
    if value == 'OBJ_CONNECTION':
        return ObjectEnum.Connection
    if value == 'OBJ_PORT':
        return ObjectEnum.Port
    if value == 'OBJ_ADDRESS':
        return ObjectEnum.Address
    raise ParseError( 'Invalid ObjectEnum: ' + value )

class EventEnum( object ):
    File, Connection = range( 2 )

def parseEventEnum( value ):
    if value == 'EVENT_FILE':
        return EventEnum.File
    if value == 'EVENT_CONNECTION':
        return EventEnum.Connection
    raise ParseError( 'Invalid EventEnum: ' + value )

class ActionEnum( object ):
    Log = range( 1 )

def parseActionEnum( value ):
    if value == 'log':
        return ActionEnum.Log
    raise ParseError( 'Invalid ActionEnum: ' + value )

def parseMultiValueDictionary( data ):
    to = {}
    for item in data:
        key   = item[ 'type' ]
        value = item[ 'value' ]
        to.setdefault( key, [] )
        to[ key ].append( value )
    return to

def parseHSPL( data ):
    to = {}
    to[ 'id' ]   = data[ 'id' ]
    to[ 'text' ] = data[ 'text' ]
    return to

class Rule( object ):

    ruleId     = None # Rule ID string
    event      = None # Event Enum
    operation  = None # Operation name (bro module name)
    action     = None # Action Enum
    parameters = {}   # Dictionary of parameters: type as a key, list of values
    conditions = {}   # Dictionary of conditions: type as a key, list of values

    def __init__( self, data ):
        self.ruleId     = data[ 'id' ]
        self.hspl       = parseHSPL( data[ 'hspl' ] )
        self.event      = parseEventEnum( data[ 'event' ] )
        self.action     = parseActionEnum( data[ 'action' ] )
        self.operation  = data[ 'operation' ]
        self.parameters = parseMultiValueDictionary( data[ 'parameters' ] )
        self.conditions = parseMultiValueDictionary( data[ 'conditions' ] )

def load( filename ):
    out = []
    with open( filename, 'r' ) as data_file:
        data = json.load( data_file )
        rules = data[ 'rules' ]
        for rule in rules:
            out.append( Rule( rule ) )
    return out
