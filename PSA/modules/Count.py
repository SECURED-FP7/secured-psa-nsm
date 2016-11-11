# -*- Mode:Python;indent-tabs-mode:nil; -*-
#
# Count.py
#
# Implements a count module that communicates with ccount.bro
#
# Author: jju / VTT Technical Research Centre of Finland Ltd., 2016
#

import logging
from collections import deque
import calendar
import time
import uuid

from broccoli import event, record_type, record, addr, port, count
from modules.BroModule import BroModule
import modules.BroEventDispatcher as BroEventDispatcher

# Record used to pass configuration rules to bro
CountConfigRecord = record_type( 'op',        # Operation: src_addr, src_port,
                                              # dst_addr, or dst_port
                                 'id',        # Rule ID
                                 'address',   # Address to match: IP or
                                              # hostname, or an empty if only
                                              # port is matched)
                                 'service' )  # Port to match (0/tcp if only
                                              # address is matched)
# Bro's response record
CountReportRecord = record_type( 'rule',            # Rule ID of matching rule
                                 'ts',              # Start time of the period
                                 'num_occurences',  # Number of events occured
                                 'first_occurence', # Timestamp of first occurence
                                 'last_occurence',  # Timestamp of last occurence
                                 'period' )         # Duration of the period (in seconds)

# Bro's record for indicating end of a measurement period (all records sent)
CountPeriodRecord = record_type( 'ts',      # Start time of the period
                                 'period' ) # Duration of the period in seconds

CountModuleKey = 'CountModuleEvent'

class BroRule( object ):

    ruleId    = None
    rule      = None
    op        = None
    address   = None
    service   = None
    counter   = None

    def __init__( self ):
        pass

    def record( self ):
        rec         = record( CountConfigRecord )
        rec.op      = str( self.op )
        rec.id      = str( self.ruleId )
        rec.address = str( self.address )
        rec.service = port( str( self.service ) + '/tcp'  )
        return rec

# Bro summaries a produced in measurement period of one minute.
# An object of this counter class is used to combine measurements
# of several adjacent perioids with each other.

# NOTE: because of how Bro SumStats works, reports are sent immediately
# when the reporting threshold is exceed: this may mean, that the reported
# count does not sum all the counts of that period. In addition, if the
# reporting period is longer than one minute, the same events may cause
# multiple log entries to be reported, as the counter simply sums counts
# of all periods fitting into the interval.
#
# Fixing these issues would require:
#  a) an event to be generated even if there is no events during the period.
#     This event should preferably come from bro (SumStats) as otherwise
#     (e.g. using a timer in Python) there is no way to know if there was no
#     event, or we are just experiencing a delay.
#  b) another option to fix this could be to always record log entries when the
#     interval has ended: at counter tick (or sometimes using a watchdog if
#     there have not been any events for a certain (long) period), before
#     discarding old periods, we could check if there is a full interval
#     (i.e., collected periods before the new timestamp form an interval)
#     and trigger a log event for that and possible the new interval.

class Counter( object ):

    DEFAULT_INTERVAL = 60
    DEFAULT_THRESHOLD = 1

    interval   = DEFAULT_INTERVAL
    threshold  = DEFAULT_THRESHOLD
    occurences = 0
    queue      = None

    def __init__( self, iv, th ):
        self.interval  = iv
        self.threshold = th
        self.queue     = deque()

    def tick( self, ts, period, count ):
        if self.queue:
            if ts == self.queue[ -1 ][ 0 ]:
                # Already handled (i.e. end-of-period report, when
                # there was also a count report this period)
                if self.queue[ -1 ][ 2 ] != count and count != 0:
                    logging.error( 'Invalid state: may have missed a count report' )
                return None

        self.occurences += count
        self.queue.append( ( ts, period, count ) )

        events = []

        # Is it possible, that we have an event?
        if self.occurences > 0 and self.occurences >= self.threshold:
            # Yes, lets iterate over the queue to find all events:
            m = len( self.queue )
            for i in range( 0, m ):
                item  = self.queue[ i ]
                start = item[ 0 ]
                end   = start + self.interval
                # Is there a full interval?
                if end <= ts + period:
                    # Yes, lets count it's occurences
                    c = 0
                    for j in range( i, m ):
                        n = self.queue[ j ]
                        if n[ 0 ] + n[ 1 ] <= end:
                            c += n[ 2 ]
                        else:
                            break

                    # and make an event, if they exceed the threshold:
                    if c >= self.threshold:
                        events.append( ( c, self.interval, start ) )
                else:
                    break

        # Let's remove all periods that are reported or cannot macth
        # any new intervals:
        self.trim( ts + period - self.interval )

        return events

    def trim( self, ts ):
        while self.queue:
            item = self.queue[ 0 ]
            if item[ 0 ] <= ts:
                self.occurences -= item[ 2 ]
                self.queue.popleft()
            else:
                break

    def reset( self ):
        self.occurences = 0
        self.queue.clear()

class CountModule( BroModule ):

    rules    = { } # BroRule (not Rule) objects!

    def __init__( self, logger ):
        super( CountModule, self ).__init__( 'ccount.bro', logger )
        BroEventDispatcher.register( CountModuleKey, self )

    def onStart( self, connection ):
        super( CountModule, self ).onStart( connection )
        self.reset( False )
        self._sendAllRules()

    def onStop( self ):
        super( CountModule, self ).onStop()

    def _sendRule( self, rule ):
        """
         Send a single rule to bro module
        """
        try:
            rec = rule.record()
            logging.info( 'Passing rule to Bro: ' + rec.id )
            self.connection.send( 'on_count_config', rec )
        except Exception as e:
            logging.warning( 'Config exception for rule: ' + rule.ruleId
                             + ' (' + rule.rule.ruleId + ')' )
            logging.exception( e )

    def _sendAllRules( self ):
        for key, rule in self.rules.iteritems():
            self._sendRule( rule )

    def _addRule( self, rule, broRule ):

        broRule.ruleId = str( uuid.uuid4().hex )
        logging.info( 'Generated ID for BroRule: ' + broRule.ruleId
                      + ' (' + rule.ruleId + ')' )
        self.rules[ broRule.ruleId ] = broRule
        broRule.rule = rule

        # Only send rules if connected to Bro
        if self.state == BroModule.State.Started:
            self._sendRule( broRule )
        #return True

    def onRule( self, rule ):
        """
        Parses rules to Bro module's format.
        """

        # TODO: currently only supports one condition per rule
        # => otherwise rule will be split to many conditions!

        # TODO: currently only supports tcp-ports. Broccoli does not
        #       support 'port/unkown'. This is compensated in the bro
        #       module by converting all ports 0/tcp to 0/unknown.
        iv = Counter.DEFAULT_INTERVAL
        if 'interval' in rule.conditions:
            items = rule.conditions[ 'interval' ]
            if len ( items ) > 1 :
                logging.error( "Rule may only have at most one 'interval' condition." )
                return False
            iv = int( items[ 0 ] )

            if iv % 60 != 0:
                logging.warning( "Only intervals multiple of one minute are supported!" )
                new = iv + 60 - iv % 60
                logging.info( "Using the next multiple (" + str( new ) + " seconds)"
                              + " instead of " + str( iv ) + " seconds" )
                iv = new

        th = Counter.DEFAULT_THRESHOLD
        if 'threshold' in rule.conditions:
            items = rule.conditions[ 'threshold' ]
            if len (items ) > 1 :
                logging.error( "Rule may only have at most one 'threshold' condition." )
                return False

            th = int( items[ 0 ] )
            if th < 1 :
                logging.error( "Invalid threshold: " + th )
                return False

        rv = False

        if 'source' in rule.conditions:
            items = rule.conditions[ 'source' ]
            for item in items:
                service = 0
                if 'port' in item:
                    service = item[ 'port' ]

                b = BroRule()
                b.counter = Counter( iv, th )
                b.op      = 'src_addr'
                b.address = item[ 'address' ]
                b.service = service
                self._addRule( rule, b )
                rv = True
                #return self._addRule( rule, b )

        if 'destination' in rule.conditions:
            items = rule.conditions[ 'destination' ]
            for item in items:
                service = 0
                if 'port' in item:
                    service = item[ 'port' ]

                b = BroRule()
                b.counter = Counter( iv, th )
                b.op      = 'dst_addr'
                b.address = item[ 'address' ]
                b.service = service
                self._addRule( rule, b )
                rv = True
                #return self._addRule( rule, b )

        if 'source_port' in rule.conditions:
            items = rule.conditions[ 'source_port' ]
            for item in items:
                b = BroRule()
                b.counter = Counter( iv, th )
                b.op      = 'src_port'
                b.address = ''
                b.service = item[ 'port' ]
                self._addRule( rule, b )
                rv = True
                #return self._addRule( rule, b )

        if 'destination_port' in rule.conditions:
            items = rule.conditions[ 'destination_port' ]
            for item in items:
                b = BroRule()
                b.counter = Counter( iv, th )
                b.op      = 'dst_port'
                b.address = ''
                b.service = item[ 'port' ]
                self._addRule( rule, b )
                rv = True
                #return self._addRule( rule, b )

        return rv


    def reset( self, resetRules = True ):
        # Only send rules if connected to Bro
        if self.state == BroModule.State.Started:
            b = BroRule()
            b.rule    = None
            b.ruleId  = 'reset'
            b.op      = 'reset'
            b.address = ''
            b.service = 0
            self._sendRule( b )
        if resetRules:
            self.rules = { }

    def _formatLogEvent( self, broRule, status ):
        rule = broRule.rule
        ts = status[ 2 ] # end time
        occurences = status[ 0 ]
        period = broRule.counter.interval

        # There should be at most one matching condition for a BroRule!

        if broRule.op == 'src_addr':
            if 'source' in rule.conditions:
                items = rule.conditions[ 'source' ]
                for item in items:
                    service = 'any'
                    if 'port' in item:
                        service = str( item[ 'port' ] )
                    return ( ts,
                             rule.ruleId,
                             rule.hspl[ 'id' ],
                             occurences,
                             period,
                             'source',
                             broRule.address,
                             broRule.service )
                             #item[ 'address' ],
                             #service )
            else:
                return None

        if broRule.op == 'dst_addr':
            if 'destination' in rule.conditions:
                items = rule.conditions[ 'destination' ]
                for item in items:
                    service = 'any'
                    if 'port' in item:
                        service = str( item[ 'port' ] )
                    return ( ts,
                             rule.ruleId,
                             rule.hspl[ 'id' ],
                             occurences,
                             period,
                             'destination',
                             broRule.address,
                             broRule.service )
                             #item[ 'address' ],
                             #service )
            else:
                return None

        if broRule.op == 'src_port':
            if 'source_port' in rule.conditions:
                items = rule.conditions[ 'source_port' ]
                for item in items:
                    return ( ts,
                             rule.ruleId,
                             rule.hspl[ 'id' ],
                             occurences,
                             period,
                             'source_port',
                             'any',
                             str( broRule.service ) )
                             #str( item[ 'port' ] ) )
            else:
                return None

        if broRule.op == 'dst_port':
            if 'destination_port' in rule.conditions:
                items = rule.conditions[ 'destination_port' ]
                for item in items:
                    return ( ts,
                             rule.ruleId,
                             rule.hspl[ 'id' ],
                             occurences,
                             period,
                             'destination_port',
                             'any',
                             str( broRule.service ) )
                             #str( item[ 'port' ] ) )
            else:
                return None

        return None

    def onEvent( self, data ):
        logging.info( "ts:   " + str( int( data.ts ) ) )

        if hasattr( data, 'rule' ):
            self.onCountEvent( data )
        else:
            self.onEndOfPeriod( data )

    def onRuleFired( self, rule, status ):
        logging.info( 'onEvent: ' + rule.ruleId + ' (' + rule.rule.ruleId + ')' )
        try:
            ev = self._formatLogEvent( rule, status )
            if ev == None:
                return

            fmt = "[%s] Rule '%s' (HSPL: %s) fired %d times within %d seconds: " \
                  "on condition '%s' with address '%s' and port '%s'\n"
            self.logger.onEvent( fmt % ev )
        except Exception as e:
            logging.error( e )

    def onCountEvent( self, data ):
        try:
            rule = self.rules[ data.rule ]
            logging.info( "rule: " + rule.ruleId + " " + str( data.num_occurences ) )
            ts = int( data.ts )
            status = rule.counter.tick( ts, data.period, data.num_occurences )
            if status:
                logging.info( "log events: " + str( len( status ) ) )
                # Rule fired!
                for entry in status:
                    self.onRuleFired( rule, entry )
            else:
                logging.debug( 'event not fired: status: ' + str( status ) )
        except Exception as e:
            logging.error( e )

    def onEndOfPeriod( self, data ):
        try:
            ts = int( data.ts )
            for key, rule in self.rules.iteritems():
                logging.info( "rule: " + rule.ruleId + " " + str( 0 ) )
                status = rule.counter.tick( ts, data.period, 0 )
                if status:
                    logging.info( "log events: " + str( len( status ) ) )
                    # Rule fired!
                    for entry in status:
                        self.onRuleFired( rule, entry )
                else:
                    logging.debug( 'event not fired: status: ' + str( status ) )
        except Exception as e:
            logging.error( e )

@event( CountReportRecord )
def report_count( data ):
    logging.info( 'Event: CountReportRecord' )
    BroEventDispatcher.dispatch( CountModuleKey, data )


@event( CountPeriodRecord )
def report_period( data ):
    logging.info( 'Event: CountPeriodRecord' )
    BroEventDispatcher.dispatch( CountModuleKey, data )

module = CountModule
