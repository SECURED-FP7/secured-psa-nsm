# -*- Mode:Bro;indent-tabs-mode:nil;-*-
#
# MHR.bro
#
# Detect file downloads that have hash values matching files in Team
# Cymru's Malware Hash Registry (http://www.team-cymru.org/Services/MHR/).
#
# Acknowledgement: this script is based on the Bro Cymru's Malware Hash Registry
#                  example script provided by the Bro Project.
#
# Author: jju / VTT Technical Research Centre of Finland Ltd., 2016
#

@load base/utils/files
@load base/utils/time
@load base/files/hash

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

@load base/frameworks/communication
@load base/frameworks/files
@load frameworks/files/hash-all-files

@load ./psa-utils

module MHR;

export {

#    # File types to attempt matching against the Malware Hash Registry.
#    const match_file_types = /application\/x-dosexec/
#                     | /application\/vnd.ms-cab-compressed/
#                     | /application\/pdf/
#                     | /application\/x-shockwave-flash/
#                     | /application\/x-java-applet/
#                     | /application\/jar/
#                     | /video\/mp4/ &redef;

    redef enum Log::ID += { LOG };

    type Info: record {
        ts:   time   &log; # Timestamp
        id:   string &log;
        msg:  string &log;
    };

    #global log_malware: event( rec: Info );

    ## The Match notice has a sub message with a URL where you can get more
    ## information about the file. The %s will be replaced with the SHA-1
    ## hash of the file.
    const match_sub_url = "https://www.virustotal.com/en/search/?query=%s" &redef;

    ## The malware hash registry runs each malware sample through several
    ## A/V engines.  Team Cymru returns a percentage to indicate how
    ## many A/V engines flagged the sample as malicious. This threshold
    ## allows you to require a minimum detection rate.
    const notice_threshold = 10 &redef;


    # Objects of this type describe file hashes that are registered locally for
    # detection. For now, the file hash type should always be 'sha1'. The
    # description field should contain a human readable description of this
    # file. This description is added to related log messages.
    # The actual file hash is used as a key in the 'local_hashes' table and
    # is not present in this record.

    type LocalHash: record {
       kind:        string; # Type of hash 'sha1'
       description: string; # Description of the hash
   };

   # Global table of locally registered file hashes, e.g., hashes that
   # are reported as malware even if they are not registered to the
   # malware registry. This is useful for testing, but also allows admins
   # to add monitoring for files not registered by Cymru.
   #
   # NOTE: use redef in a configuration file to add hashes: do not add them
   #       into this file!

   const local_hashes: table [ string ] of LocalHash = {} &redef;

   #
   #   redef MHR::local_hashes += { [ "hash-value-1" ] = [ $kind="sha1", $description="" ],
   #                                [ "hash-value-2" ] = [ $kind="sha1", $description="" ] };
   #
}

# An enumeration that describe all the possible file states (for detection):

type FileState: enum { New, Hashed, Gapped };

# Objects of this type are used to keep track of currently
# transfered files.

type CurrentFile: record {
    id:     string;
    status: FileState;
};

global current_files: table[ string ] of CurrentFile = { };

# Definition of configuration event
type MHRConfigRecord: record {
    op:   string; # Operation: add/reset
    mime: string &optional;
};

global match_mimes : set [ string ] = { } &redef;

event on_mhr_config( req: MHRConfigRecord ) {

    Log::write( MHR::LOG,
        [ $ts  = network_time(),
          $id  = req$op,
          $msg = ( req?$mime ? req$mime : "-" ) ] );

    # TODO:
    # There seem to be no way of creating patterns dynamically (after bro_init)!
    # Possible solution: redef 'match_file_types' in a bro-file and restart bro.

    switch ( req$op ) {
    case "add": # Add a new rule
         if ( req$mime !in match_mimes )
         {
             add match_mimes[ req$mime ];
         }
         break;
    case "reset":
          # Remove all rules:
          match_mimes = set( );
          break;
    default: # Invalid operation
           return;
    }
}

# A log event for detected malware

type MHRRecord: record {
    id:       string;  # Operation ID
    ts:       time;    # File detection time
    hash:     string;  # Sha1 hash
    fid:      string;  # Bro's file ID
    name:     string;  # Filename, if available
    service:  string;  # Service (e.g., HTTP) using which the file was loaded
    source:   string;  # List of space separated addresses
    mime:     string;  # Mime type of the file
    detected: time;    # First time the malware was detected
    rate:     count;   # Times the malware has been detected
    url:      string;  # VirusTotal URL for the malware
    msg:      string;  # Optional message (not used in 'macth' unless its a local match)
};

# Event handler:

global mhr_alert: event( data: MHRRecord );

# A log event for hashed file, errors, etc.

type MHRLogRecord: record {
    id:       string;  # Operation ID
    ts:       time;    # File detection time
    hash:     string;  # Sha1 hash
    fid:      string;  # Bro's file ID
    name:     string;  # Filename, if available
    service:  string;  # Service (e.g., HTTP) using which the file was loaded
    source:   string;  # List of space separated addresses
    mime:     string;  # Mime type of the file
    msg:      string;  # Optional message (not used in 'macth' unless its a local match)
};

# Event handler:

global mhr_log: event( data: MHRLogRecord );

# Auxilliary function to formatting and sending MHRLogRecords:

function send_log_event( f: fa_file, id: string, hash: string, msg: string )
{
    local source = "";

    for ( i in f$info$tx_hosts )
    {
        source = cat( source, " ", i );
    }

    local rec: MHRLogRecord;
    rec$id       = id;
    rec$ts       = f$info$ts;
    rec$hash     = hash;
    rec$fid      = f$id;
    rec$name     = ( f$info?$filename ? f$info$filename : "" );
    rec$service  = f$source;
    rec$source   = source;
    rec$mime     = ( f$info?$mime_type ? f$info$mime_type : "" );
    rec$msg      = msg;

    event mhr_log( rec );
}

function send_alert_event( f: fa_file,
                           hash: string,
                           url: string,
                           detected: time,
                           rate: count,
                           msg: string )
{
    local source = "";

    for ( i in f$info$tx_hosts )
    {
        source = cat( source, " ", i );
    }

    local rec: MHRRecord;
    rec$id       = "match";
    rec$ts       = f$info$ts;
    rec$hash     = hash;
    rec$fid      = f$id;
    rec$name     = ( f$info?$filename ? f$info$filename : "" );
    rec$service  = f$source;
    rec$source   = source;
    rec$mime     = f$info$mime_type;
    rec$rate     = rate;
    rec$detected = detected;
    rec$url      = url;
    rec$msg      = msg;

    event mhr_alert( rec );
}

# Actual registry lookup:

function do_mhr_lookup( hash: string, f: fa_file )
{
    # Uncomment for testing: a known malware hash brbbot.exe
    #hash="2c9e509de4b3ec03589b5c95baba06a9387195e6";

    Log::write( MHR::LOG,
                [ $ts  = network_time(),
                  $id  = "Performing lookup",
                  $msg = f$id ] );

    # Log all hashed files at this point
    send_log_event( f, "log", hash, "file hashed" );

    local hash_domain = fmt( "%s.malware.hash.cymru.com", hash );
    when ( local MHR_result = lookup_hostname_txt( hash_domain ) )
    {
        # Data is returned as "<dateFirstDetected> <detectionRate>"
        local MHR_answer = split_string1( MHR_result, / / );

        if ( |MHR_answer| == 2 )
        {
            local mhr_detect_rate = to_count( MHR_answer[ 2 ] );
            if ( mhr_detect_rate >= notice_threshold )
            {
                local mhr_first_detected = double_to_time( to_double( MHR_answer[ 1 ] ) );
                #local readable_first_detected = strftime("%Y-%m-%d %H:%M:%S", mhr_first_detected);
                #local message = fmt( "Malware Hash Registry Detection rate: %d%%  Last seen: %s", mhr_detect_rate, readable_first_detected );
                local virustotal_url = fmt( match_sub_url, hash );
                # We don't have the full fa_file record here in order to
                # avoid the "when" statement cloning it (expensive!).

                Log::write( MHR::LOG,
                    [ $ts  = network_time(),
                      $id  = "Macth",
                      $msg = hash ] );

                send_alert_event( f, hash, virustotal_url, mhr_first_detected,
                                  mhr_detect_rate, "" );
            }
            else
            {
                Log::write( MHR::LOG,
                            [ $ts  = network_time(),
                            $id  = "No match",
                            $msg = f$id ] );

            }
        }
        else # Do a local lookup
        {
            Log::write( MHR::LOG,
                        [ $ts  = network_time(),
                          $id  = "Performing local lookup",
                          $msg = f$id ] );

            if ( hash in local_hashes )
            {
                local data = local_hashes[ hash ];

                Log::write( MHR::LOG,
                    [ $ts  = network_time(),
                    $id  = "Macth",
                    $msg = hash ] );

                send_alert_event( f, hash, "", current_time(),
                                  0, data$description );
            }
            else
            {
                Log::write( MHR::LOG,
                            [ $ts  = network_time(),
                            $id  = "No match",
                            $msg = f$id ] );

            }
        }
    }
}

function check_mime( mime_type : string ) : bool
{
    # Check for direct match:
    if ( mime_type in match_mimes )
    {
        return T;
    }
    else # Check for patrial matches
    {
        # A clumsy way of doing this, but we cannot generate pattern
        # dynamically :'(

        for ( mime in match_mimes )
        {
            # If file's mime-type string contains 'mime':
            if ( strstr( mime_type, mime ) != 0 )
            {
                return T;
            }
        }
    }

    return F;
}

event file_hash( f: fa_file, kind: string, hash: string )
{
    Log::write( MHR::LOG,
                [ $ts  = network_time(),
                  $id  = "File hashed",
                  $msg = hash ] );

    # Only handle sha1 hashes
    if ( kind == "sha1" )
    {
        # Mark file as hashed
        if ( f$id !in current_files )
        {
            current_files[ f$id ] = CurrentFile( $id     = f$id,
                                                 $status = Hashed );
        }
        else
        {
            current_files[ f$id ]$status = Hashed;
        }

        Log::write( MHR::LOG,
                    [ $ts  = network_time(),
                      $id  = "Checking mime",
                      $msg = f$info?$mime_type ] );

        if ( f$info?$mime_type  )
        {
            if ( check_mime( f$info$mime_type ) )
            {
                do_mhr_lookup( hash, f );
            }
        }
        else # mime-type not available
        {
            send_log_event( f, "log", hash, "mime-type missing" );
        }
    }
}

# Make note of every detected file in order to follow their state:
event file_new( f: fa_file )
{
    Log::write( MHR::LOG,
                [ $ts  = network_time(),
                  $id  = "File detected",
                  $msg = f$id ] );

    current_files[ f$id ] = CurrentFile( $id     = f$id,
                                         $status = New );
}

# Make note that not all file parts could be detected (there will be no hash)
event file_gap( f: fa_file, offset: count, len: count )
{
    Log::write( MHR::LOG,
                [ $ts  = network_time(),
                  $id  = "Gap detected",
                  $msg = f$id ] );

    if ( f$id !in current_files )
    {
        current_files[ f$id ] = CurrentFile( $id     = f$id,
                                         $status = Gapped );
    }
    else
    {
        current_files[ f$id ]$status = Gapped;
    }
}

# Remove file state and send an event in case of
# any errors were detected.
# NOTE: this function might be called before the
#       hash lookup returns: nothing during the
#       lookup or after it should depend on the
#       stored file information (which is removed
#       in this function)!

event file_state_remove( f: fa_file )
{
    Log::write( MHR::LOG,
                [ $ts  = network_time(),
                  $id  = "File ended",
                  $msg = f$id ] );

    if ( f$id !in current_files )
    {
        # We are fucked up!
        return;
    }

    local entry = current_files[ f$id ];

    switch ( entry$status ) {
    case New: fallthrough;
    case Gapped:
        if ( f$info?$mime_type  )
        {
            if ( check_mime( f$info$mime_type ) )
            {
                send_log_event( f, "log", "", "file not hashed" );
            }
        }
        else
        {
            send_log_event( f, "log", "", "mime-type missing" );
        }

        break;
    case Hashed:
        # Nothing to do: event is sent if the hash matched
        break;
    default:
        # TODO: Log: Invalid status!
        break;
    }

    delete current_files[ f$id ];
}



event bro_init() &priority=9
{
    #Log::create_stream( LOG, [ $columns=Info, $ev=log_malware ] ); # return True if ok
    if ( !Log::create_stream( LOG, [ $columns=Info ] ) )
    {
        print "MHR.bro: Log creation failed!";
    }

    Log::write( MHR::LOG,
                [ $ts  = network_time(),
                  $id  = "Init",
                  $msg = "" ] );

    PSA::subscribe_events( /on_mhr_config/ );
}