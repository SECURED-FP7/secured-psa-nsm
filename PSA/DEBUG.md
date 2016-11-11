# Adding extra Bro scripts

This document describes how to load user defined Bro NSM scripts on Bro PSA.
Since BroPSA loads scripts dynamically, normal Bro configuration files
cannot be used (easily) for debugging, e.g., for redefining variables. This
document describes two approaches of adding such Bro scripts.

Examples in this document consider adding a local repository of file hashes for
the 'detect-MHR' module. This feature can be used, e.g., for testing. Normally,
these file hashes can be added simply by redefining the bro variable
MHR::local_hashes as shown in the example below. However, because of BroPSA's
dynamic module loading, this is not possible.

## Option 1: Using pre- and post-init scripts

BroPSA allows users to define Bro scripts that are loaded before or after the
actual BroPSA module Bro scripts are loaded. Pre- and post-init scripts must be
placed on files called *modules/pre-init.bro* or *modules/post-init.bro*,
respectively. If either of these files exist when BroPSA's configuration is set,
then it will be automatically added into the BroPSA's Bro configuration.

**Example**:

Create file *modules/post-init.bro* with the following content and then start
BroPSA normally:

```
redef ignore_checksums = T;
redef tcp_max_initial_window = 0;
redef tcp_max_above_hole_without_any_acks = 0;
redef tcp_excessive_data_without_further_acks = 0;

redef MHR::local_hashes += { [ "afba7d3f3addd136afb4b13a49703e979fb4f590" ]
                               = [ $kind="sha1", $description="detected T170.pdf" ],
                             [ "f2e5efd7b47d1fb5b68d355191cfed1a66b82c79" ]
                               = [ $kind="sha1", $description="detected 7z1514.exe" ] };
```

## Option 2: Using BroLoader-module

BroLoader-module is a dummy BroPSA module that does not do anything else, but
triggers a Bro script file called modules/config.bro to be loaded. This script
file can be used to load certain Bro scripts dynamically. Compared to using pre-
and post-init scripts BroLoader-module offers extra flexibility: it can be used
to load Bro scripts between BroPSA modules, not just before or after all the
modules are loaded. Since BroLoader is a normal BroPSA module, it is loaded
according to the load order defined by the BroPSA's configuration file.


**Example**:
Create file *modules/config.bro* with the following content:

```
redef ignore_checksums = T;
redef tcp_max_initial_window = 0;
redef tcp_max_above_hole_without_any_acks = 0;
redef tcp_excessive_data_without_further_acks = 0;

redef MHR::local_hashes += { [ "afba7d3f3addd136afb4b13a49703e979fb4f590" ]
                               = [ $kind="sha1", $description="detected T170.pdf" ],
                             [ "f2e5efd7b47d1fb5b68d355191cfed1a66b82c79" ]
                               = [ $kind="sha1", $description="detected 7z1514.exe" ] };
```

Add a new rule to *psaConfig/psaconf* after any rules related to the
'detect-MHR' module (e.g. as the last rule). This rule will cause
*modules/config.bro* file to be loaded. Start BroPSA normally.

```
     { "id": "load-config",
       "hspl": {
         "id": "-",
         "text": "-"
       },
       "event": "EVENT_FILE",
       "operation": "load-config",
       "parameters": [ ],
       "action": "log",
       "conditions": []
     }
```
