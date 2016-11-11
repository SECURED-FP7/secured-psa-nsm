# -*- Mode:Bro;indent-tabs-mode:nil;-*-
#
# count.bro
#
# Bro script that can be configured dynamically to count established connections
# that fulfill certain conditions, such as, source or destination addresses or
# ports.
#
# Acknowledgement: this script is originally based on the Bro SumStats example
#                  script provided by the Bro Project.
#
# Author: jju / VTT Technical Research Centre of Finland Ltd., 2016
#

@load base/protocols/conn
@load base/protocols/dhcp
@load base/protocols/dnp3
@load base/protocols/dns
@load base/protocols/ftp
@load base/protocols/http
@load base/protocols/irc
@load base/protocols/modbus
@load base/protocols/pop3
@load base/protocols/radius
@load base/protocols/snmp
@load base/protocols/smtp
@load base/protocols/socks
@load base/protocols/ssh
@load base/protocols/ssl
@load base/protocols/syslog
@load base/protocols/tunnels

@load base/files/hash
@load base/files/extract
@load base/files/unified2
@load base/files/x509

@load base/frameworks/communication
@load base/frameworks/sumstats

@load ./psa-utils

module CCount;

# Definitions for logging framework:
export {

    redef enum Log::ID += { LOG };

    type Info: record {
        ts:      time   &log; # Timestamp
        op:      string &log; # Type of event
        id:      string &log; # Name of the rule
        address: addr   &log; # IP address
        service: port   &log;
    };

    #global log_cc: event( rec: Info );
}

# Definition of configuration event
type CountConfigRecord: record {
    op:        string; # Operation
    id:        string; # Name of the rule
    address:   string; # Related address, an IP address or a hostname
    service:   port;   # Related port
};

# Definition of configuration event
type Rule : record {
    id:        string;    # Name of the rule
    op:        string;    # Operation
    address:   set[addr]; # A set of related IP address
    service:   port;      # Port
};

# Table of currently active rules:
global rules : table[ string ] of Rule = {};

# Add a new rule to rules table:
function add_rule( cc: CountConfigRecord, addresses: set[ addr ] ) {

    # Log 'any IP'
    if ( |addresses| == 0 ) {
        Log::write( CCount::LOG, [ $ts      = network_time(),
                                   $op      = cc$op,
                                   $id      = cc$id,
                                   $address = 0.0.0.0,
                                   $service = cc$service ]);
    }

    # Log one or more IPs
    for ( a in addresses ) {
        Log::write( CCount::LOG, [ $ts      = network_time(),
                                   $op      = cc$op,
                                   $id      = cc$id,
                                   $address = a,
                                   $service = cc$service ]);
    }

    rules[ cc$id ] = Rule( $id      = cc$id,
                           $op      = cc$op,
                           $address = addresses,
                           $service = cc$service );
}

# Event handler for configuration events:
event on_count_config( cc: CountConfigRecord ) {

    # To fix missing protocol 'unknown' in broccoli python bindings
    if ( cc$service == 0/tcp )
    {
        cc$service = 0/unknown;
    }

    switch ( cc$op ) {
    case "src_addr": fallthrough;
    case "src_port": fallthrough;
    case "dst_addr": fallthrough;
    case "dst_port":
         if ( cc$id in rules ) {
             delete rules[ cc$id ];
         }

         # The address is either an IP address, a hostname, or empty.
         # A hostname may resolve to several IP addresses, so we deal
         # with a set of addresses instead of a single address.

         local addresses: set[ addr ];

         # For some reason, |string|>0 doesn't fire: is this because of
         # something made by broccoli-python string conversion?

         if ( cc$address != "" ) {

             # If we have a single ip, convert it to 'addr':
             if ( is_valid_ip( cc$address ) ) {
                 add addresses[ to_addr( cc$address ) ];
             }
             else # otherwise, do a lookup for IP addresses:
             {
                 # This will block, so let's do it async:
                 when ( local h = lookup_hostname( cc$address ) ) {
                     add_rule( cc, h );
                 }
                 return;
             }
         } else {
             # Empty set of addresses (check port only)
         }

         add_rule( cc, addresses );
         break;
    case "reset": # Delete a rule

        Log::write( CCount::LOG, [ $ts      = network_time(),
                                   $op      = cc$op,
                                   $id      = cc$id,
                                   $address = 0.0.0.0,
                                   $service = cc$service ]);

        for ( key in rules )
        {
              delete rules[ key ];
        }
        break;
    default: # Invalid operation
           return;
    }

}

# Attaches a observer to each connection for each rule that it fulfills.
#event connection_established( c: connection ) {
event new_connection( c: connection ) {

    # TODO: a faster way to find correct rules should be implemented.

    for ( key in rules )
    {
        local rule = rules[ key ];

        switch ( rule$op )
        {
        case "src_addr":
            if ( c$id$orig_h in rule$address
                && ( rule$service == 0/unknown || rule$service == c$id$orig_p ) )
            {
                SumStats::observe( "conn established",
                    SumStats::Key( $str = rule$id ),
                    SumStats::Observation( $num = 1 ) );

                Log::write( CCount::LOG, [ $ts      = network_time(),
                                           $op      = "add_observer",
                                           $id      = rule$op,
                                           $address = c$id$orig_h,
                                           $service = c$id$orig_p ]);
            }
             break;
        case "dst_addr":
            if ( c$id$resp_h in rule$address
                && ( rule$service == 0/unknown || rule$service == c$id$resp_p ) )
            {
                SumStats::observe( "conn established",
                    SumStats::Key( $str = rule$id ),
                    SumStats::Observation( $num = 1 ) );

                Log::write( CCount::LOG, [ $ts      = network_time(),
                                           $op      = "add_observer",
                                           $id      = rule$op,
                                           $address = c$id$resp_h,
                                           $service = c$id$resp_p ]);
            }
            break;
        case "src_port":
            if ( rule$service == c$id$orig_p )
            {
                 SumStats::observe( "conn established",
                    SumStats::Key( $str = rule$id ),
                    SumStats::Observation( $num = 1 ) );

                Log::write( CCount::LOG, [ $ts      = network_time(),
                                           $op      = "add_observer",
                                           $id      = rule$op,
                                           $address = c$id$orig_h,
                                           $service = c$id$orig_p ]);
            }
            break;
        case "dst_port":
            if ( rule$service == c$id$resp_p )
            {
                SumStats::observe( "conn established",
                    SumStats::Key( $str = rule$id ),
                    SumStats::Observation( $num = 1 ) );

                Log::write( CCount::LOG, [ $ts      = network_time(),
                                           $op      = "add_observer",
                                           $id      = rule$op,
                                           $address = c$id$resp_h,
                                           $service = c$id$resp_p ]);
            }
            break;
        default: # Invalid operation
           return;
        }
    }
}

# Events to send to Count.py

# Measurement report:
type CountReportRecord: record {
    rule:            string; # Rule (ID) of this measurement
    ts:              time;   # Timestamp for this measurement (start time)
    num_occurences:  double; # Total number of occurences within measurement period
    first_occurence: time;   # Timestamp of first occurence
    last_occurence:  time;   # Timestamp of last occurence
    period:          count;  # Measurement perioid in seconds
};

# End of measurement perioid notification:

type CountPeriodRecord: record {
    ts:      time;  # Timestamp for this measurement (start time)
    period:  count; # Measurement perioid in seconds
};

global report_count: event( data: CountReportRecord );
global report_period: event( data: CountPeriodRecord );

event bro_init() &priority=9
{
    #Log::create_stream( CCount::LOG, [ $columns = CCount::Info,
    #                                   $ev      = log_cc ] );

    if ( !Log::create_stream( CCount::LOG, [ $columns = CCount::Info ] ) )
    {
        print "ccount.bro: Log creation failed!";
    }

    Log::write( CCount::LOG, [ $ts      = network_time(),
                               $op      = "init",
                               $id      = "",
                               $address = 0.0.0.0,
                               $service = 0/unknown ] );

    PSA::subscribe_events( /on_count_config/ );

    # Create the reducer.
    # The reducer attaches to the "conn established" observation stream
    # and uses the summing calculation on the observations.
    # There will be one result for each connection responder (c$id$resp_h)

    local r1 = SumStats::Reducer( $stream = "conn established",
                                  $apply  = set( SumStats::SUM ) );

    # Create the final sumstat.
    # We give it an arbitrary name and make it collect data every minute.
    # The reducer is then attached and a $epoch_result callback is given
    # to finally do something with the data collected.
    SumStats::create( [ $name     = "counting connections",
                        $epoch    = 1min,
                        $reducers = set( r1 ),
                        $epoch_result( ts:     time,
                                       key:    SumStats::Key,
                                       result: SumStats::Result ) = {

                                   # This is the body of the callback that is called when a single 
                                   # result has been collected.  We are just printing the total number
                                   # of connections that were seen.  The $sum field is provided as a 
                                   # double type value so we need to use %f as the format specifier.

                                   Log::write( CCount::LOG, [ $ts      = network_time(),
                                                              $op      = "log",
                                                              $id      = key$str,
                                                              $address = 0.0.0.0,
                                                              $service = 0/tcp ]);

                                   local stats = result[ "conn established" ];
                                   local data: CountReportRecord;
                                   data$rule            = key$str;
                                   data$ts              = ts;
                                   data$num_occurences  = stats$sum;
                                   data$first_occurence = stats$begin;
                                   data$last_occurence  = stats$end;
                                   data$period          = 60;

                                   # send event for our broccoli
                                   event report_count( data );
                               },
                               $epoch_finished( ts: time ) = {

                                   Log::write( CCount::LOG, [ $ts      = network_time(),
                                                              $op      = "end",
                                                              $id      = "end",
                                                              $address = 0.0.0.0,
                                                              $service = 0/tcp ]);

                                   local data: CountPeriodRecord;
                                   data$ts              = ts;
                                   data$period          = 60;

                                   # send event for our broccoli
                                   event report_period( data );
                               } ] );
}
