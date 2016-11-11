Testing:

#1
mvn clean install

#2
./test.sh examples/example_mspl_log_0.xml bro_json_config.json

- This will validate the given M2L with schema/MSPL_XML_Schema.xsd and then convert the M2L into bro JSON config.

