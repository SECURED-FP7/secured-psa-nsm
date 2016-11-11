# This file can be used to make Bro PSA Detect-MHR module to consider the files
# fecthed by the following scripts to be considered as malware:
#
#   download_pdf.sh
#   download_exe.sh
#
# Usage: copy this files under Bro PSA's modules directory
# (PSA/modules/post-init.bro) before booting Bro PSA.
#

redef ignore_checksums = T;
redef tcp_max_initial_window = 0;
redef tcp_max_above_hole_without_any_acks = 0;
redef tcp_excessive_data_without_further_acks = 0;

redef MHR::local_hashes += { [ "afba7d3f3addd136afb4b13a49703e979fb4f590" ]
                               = [ $kind="sha1", $description="detected T170.pdf" ],
                             [ "f2e5efd7b47d1fb5b68d355191cfed1a66b82c79" ]
                               = [ $kind="sha1", $description="detected 7z1514.exe" ] };
