##! Local site policy. It will be dynamically updated when policy is enabled/disabled 
##!
##! This file will not be overwritten when upgrading or reinstalling!
# Note: Bro supports writing to files, but not reading from them.


# Disable checksum validation
redef ignore_checksums = T;
redef tcp_max_initial_window = 0;
redef tcp_max_above_hole_without_any_acks = 0;
redef tcp_excessive_data_without_further_acks = 0;

# Implemented policies

# Enables pinging a bro node
#@load /home/admini/SECURED/policies/broping-record.bro

# Count connections
#@load /home/admini/SECURED/policies/count_conns.bro

# Weak keys notice
#@load /home/admini/SECURED/policies/weak-keys.bro

# Hash calculation
#@load /home/admini/SECURED/policies/hash-files.bro

# Interesting scripts

# Log some information about web applications being used by users 
# on your network.
#@load misc/app-stats

# Scripts that do asset tracking.
#@load protocols/conn/known-hosts
#@load protocols/conn/known-services
#@load protocols/ssl/known-certs

# This script enables SSL/TLS certificate validation.
#@load protocols/ssl/validate-certs
# This script prevents the logging of SSL CA certificates in x509.log
#@load protocols/ssl/log-hostcerts-only
# Uncomment the following line to check each SSL certificate hash against the ICSI
# certificate notary service; see http://notary.icsi.berkeley.edu .
#@load protocols/ssl/notary

# Enable MD5 and SHA1 hashing for all files.
#@load frameworks/files/hash-all-files

# Detect SHA1 sums in Team Cymru's Malware Hash Registry.
#@load frameworks/files/detect-MHR




# Some general scripts and some other scripts that might be interesting

# This script logs which scripts were loaded during each run.
@load misc/loaded-scripts

# Apply the default tuning scripts for common tuning settings.
@load tuning/defaults

# Load the scan detection script.
#@load misc/scan

# Detect traceroute being run on the network.  
#@load misc/detect-traceroute

# Generate notices when vulnerable versions of software are discovered.
# The default is to only monitor software found in the address space defined
# as "local".  Refer to the software framework's documentation for more 
# information.
#@load frameworks/software/vulnerable

# Detect software changing (e.g. attacker installing hacked SSHD).
#@load frameworks/software/version-changes

# This adds signatures to detect cleartext forward and reverse windows shells.
#@load-sigs frameworks/signatures/detect-windows-shells

# Load all of the scripts that detect software in various protocols.
#@load protocols/ftp/software
#@load protocols/smtp/software
#@load protocols/ssh/software
#@load protocols/http/software
# The detect-webapps script could possibly cause performance trouble when 
# running on live traffic.  Enable it cautiously.
#@load protocols/http/detect-webapps

# This script detects DNS results pointing toward your Site::local_nets 
# where the name is not part of your local DNS zone and is being hosted 
# externally.  Requires that the Site::local_zones variable is defined.
#@load protocols/dns/detect-external-names

# Script to detect various activity in FTP sessions.
#@load protocols/ftp/detect

# If you have libGeoIP support built in, do some geographic detections and 
# logging for SSH traffic.
#@load protocols/ssh/geo-data
# Detect hosts doing SSH bruteforce attacks.
#@load protocols/ssh/detect-bruteforcing
# Detect logins using "interesting" hostnames.
#@load protocols/ssh/interesting-hostnames

# Detect SQL injection attacks.
#@load protocols/http/detect-sqli

# Uncomment the following line to enable detection of the heartbleed attack. Enabling
# this might impact performance a bit.
#@load policy/protocols/ssl/heartbleed
