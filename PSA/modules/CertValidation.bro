# -*- Mode:Bro;indent-tabs-mode:nil;-*-
#
# CertValidation.bro
#
# Certificate Validation module
#
# Heavily based on validate-certs.bro script
#
# Author: sl / VTT / 2016
#

@load ./psa-utils
@load protocols/ssl/validate-certs

module CVModule;

export {

    redef enum Log::ID += { LOG };

    type Info: record {
        ts:      time   &log; # Timestamp
        op:      string &log; # Type of event
        id:      string &log; # Name of the rule
    };

event on_cv_config( req: CVConfigRecord ) {
    Log::write( CVModule::LOG,
        [ $ts  = network_time(),
          $id  = req$op,
          $msg = ( req?$mime ? req$mime : "-" ) ] );

    # Possibly setting up some root certs to trust

    switch ( req$op ) {
    case "add": # Add a root cert
         break;
    default: # Invalid operation
           return;
    }
}


# this event occurs whenever a SSL connection is established
event ssl_established( c: connection ) &priority=3
{
    logging.info("SSL established!");

    local cert = c$ssl$cert_chain[0]$x509$certificate;
	
    local id = "";
    local hashes = "";
    for ( i in c$ssl$cert_chain )
    {
	if ( i > 0 )
	hashes += " ";
	hashes += c$ssl$cert_chain[i]$sha1;

    }
    local name = c$ssl$cert_chain[0]$x509$certificate$subject;
    local message = c$ssl$validation_status;
    logging.info( id + " \"" + name + "\" " + hashes + " \"" + message + "\"";

    send_log_event( id, name, hashes, msg );
}

# A log event for cert validations.

type CVLogRecord: record {
    id:       string;  # Operation ID
    ts:	      string;  # time
    hashes:   string;  # Cert hashes of the whole chain
    name:     string;  # Cert subject
    msg:      string;  # Trusted, expired or some other reason.
};

# Event handler:

global cv_log: event( data: CVLogRecord );

# Auxilliary function to formatting and sending CVLogRecords:

function send_log_event( id: string, name: string, hashes: string, msg: string )
{
    local source = "";

    local rec: CVLogRecord;
    rec$ts	 = network_time();
    rec$id       = id;
    rec$hashes   = hashes;
    rec$name     = name;
    rec$msg      = msg;

    event cv_log( rec );
}


event bro_init() &priority=9
{
    if ( !Log::create_stream( LOG, [ $columns=Info ] ) )
    {
        print "CertValidation.bro: Log creation failed!";
    }

    Log::write( CVModule::LOG,
                [ $ts  = network_time(),
                  $id  = "Init",
                  $msg = "" ] );

    PSA::subscribe_events( /on_cv_config/ );
    PSA::subscribe_events( /ssl_established/ );
}

}
