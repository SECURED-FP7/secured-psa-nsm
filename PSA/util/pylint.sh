#!/bin/sh

pylint *.py modules > pylint.out

echo "done: check pylint.out"
echo ""
exit 0
