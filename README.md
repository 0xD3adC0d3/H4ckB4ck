Usage: H4ckB4ck.py [-h] [-b] [-f] [-i] [-l] [-n] [-r REPORT] [-s] [-t TARGET] [-v] [-w]

Hackback will run information gathering and offensive actions against IP addresses that are banned in your fail2ban.log log file. It requires your machine to be protected by Fail2ban and
the fail2ban.log file in the same folder as the script is running.

optional arguments:
  -h, --help            show this help message and exit
  -b, --bruteforce      Run a bruteforce attack against a target in the database (need to provide the target id with port 22 open using the -t argument, more to come later)
  -f, --force           Force the action to be launched (new attack) even if already present in the database
  -i, --init            Initialize de database and imports the log file
  -l, --listTargets     List the targets in the database
  -n, --nikto           Run a nikto scan against targets in the database (need to provide the target id with port 80 or 443 open)
  -r REPORT, --report REPORT
                        The report id for the desired action on the desired target
  -s, --scan            Run a port scan against the target in the database (need to provide the target id)
  -t TARGET, --target TARGET
                        The target id for the desired action
  -v, --verbose         Enable verbose output
  -w, --whois           Fetch whois information against the target in the database (need to provide the target id)


Dependency for whois : pip install python-whois

Ideas not implemented to keep it safe:
  - nmap scan
  - nikto scan if port 80 or 443 is open
  - bruteforce attack if port 21,22,23,445 (or) is open
  - run all the actions (-x) on all the targets. This may produce issues with APIs (Shodan) and take a lot of ressources
