#/bin/sh

if [ ! -f "$1" ]; then
    echo "usage: $0 FILE"
    exit 1
fi

xmllint --schema ./schema/MSPL_XML_Schema.xsd --noout --nonet --dropdtd $1
