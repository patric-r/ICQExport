ICQExport
=========

Minimalistic ICQ message history HTML exporter (prior to ICQ 2003b)

Works directly on the database file, no ICQ installation required.<br>
It works on a best-effort/heuristic approach and therefore tries to extract ICQ messages from corrupted/truncated database files as well.

Currently only tested with ICQ2000b database files, however, it should work with the database files from the following versions:
* ICQ 99a
* ICQ 99b
* ICQ 2000a
* ICQ 2000b
* ICQ 2001a
* ICQ 2001b
* ICQ 2002a
* ICQ 2003a 

If not, create an issue or do a pull request.

Quick start
===========

1. Download https://github.com/MRalwasser/ICQExport/blob/master/ICQExport/ICQExport.jar?raw=true
2. Execute downloaded jar file (java required)
3. Choose ICQ database file (often inside C:\Program Files\ICQ\2000b\ )
4. Wait until export finishes (browser will open and  navigate to the generated html export)

Thank you
================

Thanks to Miranda project for providing a very helpful description of the database format:
https://raw.githubusercontent.com/miranda-ng/miranda-ng/master/plugins/Import/docs/import-ICQ_Db_Specs.txt

License
=======

Licensed under Apache Software License 2.0







