Usage: H4ckB4ck.py [-h] [-a] [-d DATABASE] [-e LOGSFILE] [-f] [-g] [-i] [-l] [-r REPORT] [-s] [-t TARGET] [-v] [-w] [-x]

Hackback will run information gathering (osint) against IP addresses that are banned in your fail2ban.log log file. It requires your
machine to be protected by Fail2ban.

optional arguments:
  -h, --help            show this help message and exit
  -a, --allLogs         Fetch all logs regarding a target in the database (need to provide the target id using the -t argument)
  -d DATABASE, --database DATABASE
                        The database file to create. ./hackback.db is the default
  -e LOGSFILE, --logsfile LOGSFILE
                        The log file to populate the database, use it with -i or keep ./fail2ban.log as default
  -f, --force           Force the action to be launched (new attack) even if already present in the database
  -g, --geoip           Fetch GeoIP information against the target in the database (need to provide the target id)
  -i, --init            Initialize de database and imports the log file
  -l, --listTargets     List the targets in the database
  -r REPORT, --report REPORT
                        The report id for the desired action on the desired target
  -s, --shodan          Fetch shodan information against the target in the database (need to provide the target id)
  -t TARGET, --target TARGET
                        The target id for the desired action
  -v, --verbose         Enable verbose output
  -w, --whois           Fetch whois information against the target in the database (need to provide the target id)
  -x, --allActions      Fetch geoip, shodan and whois information against the target in the database (need to provide the target id)

Dependency for whois : pip install python-whois

Ideas not implemented to keep it safe:
  - nmap scan
  - nikto scan if port 80 or 443 is open
  - bruteforce attack if port 21,22,23,445 (or) is open
  - run all the actions (-x) on all the targets. This may produce issues with APIs (Shodan) and take a lot of ressources
