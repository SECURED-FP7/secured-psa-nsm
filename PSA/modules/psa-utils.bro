# -*- Mode:Bro;indent-tabs-mode:nil;-*-
#
# psa-utils.bro
#
# Generic utilities for all Bro PSA modules.
#
# Author: jju / VTT Technical Research Centre of Finland Ltd., 2016

@load base/frameworks/communication

module PSA;

export {
    global subscribe_events: function( events: pattern );
}

function subscribe_events( events : pattern )
{

    if ( "PSA" in Communication::nodes )
    {
        local node = Communication::nodes[ "PSA" ];
        if ( node?$events )
        {
            local evs = merge_pattern( node$events, events );
            node$events = evs;
        }
        else
        {
            node$events = events;
        }
    }
    else
    {
        Communication::nodes[ "PSA" ] = [ $host    = 127.0.0.1,
                                          $events  = events,
                                          $connect = F,
                                          $ssl     = F ];
    }
}