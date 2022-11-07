#!/usr/bin/python3

import argparse
import logging
import sys
import sqlite3
from sqlite3 import Error
from os.path import exists
from datetime import datetime
import base64
import whois
import GeoIP
import shodan

SHODAN_API_KEY = "CENSORED"

def createConnection(dbfile):
    conn = None
    try:
        conn = sqlite3.connect(dbfile)
    except Error as e:
        print(e)
    return conn

def createTable(conn, sql):
    try:
        c = conn.cursor()
        c.execute(sql)
    except Error as e:
        print(e)

def insertLog(conn, row):
    sql = ''' INSERT INTO logs(log_date,log_time,action,ip_address,find_date,find_time) VALUES(?,?,?,?,?,?) '''
    cur = conn.cursor()
    cur.execute(sql, row)
    conn.commit()
    return cur.lastrowid

def initdb(dbfile, logfile, force):
    if exists(logfile) == False:
        logging.info("The logfile " + logfile + " doesn't exist. Specify a custom one with -e or place fail2ban.log in the same directory as this script")
        return
    if exists(dbfile) and force == False:
        logging.info("The database already exists. Please delete before initialization or use -f to add the data")
        return
    elif exists(dbfile) == False and force:
        logging.info("Take it easy! The database file doesn't exist yet, don't try to force on the first attempt!")
        return
    if exists(dbfile) and force:
        logging.info("Adding new log file to the database")

    conn = createConnection(dbfile)

    if conn is not None:
        if force == False:
            logging.info("Database successfully created")
            sql_create_logs_table = """ CREATE TABLE IF NOT EXISTS logs (
                                            id integer PRIMARY KEY,
                                            log_date text NOT NULL,
                                            log_time text NOT NULL,
                                            action text NOT NULL,
                                            ip_address text NOT NULL,
                                            find_date text NOT NULL,
                                            find_time text NOT NULL
                                        ); """

            sql_create_targets_table = """ CREATE TABLE IF NOT EXISTS targets (
                                            id integer PRIMARY KEY,
                                            ip_address text NOT NULL,
                                            last_whois text,
                                            last_shodan text,
                                            last_location text
                                        ); """

            sql_create_whois_table = """CREATE TABLE IF NOT EXISTS whois (
                                        id integer PRIMARY KEY,
                                        ip_address text NOT NULL,
                                        scan_date text NOT NULL,
                                        scan_time text NOT NULL,
                                        record text NOT NULL
                                    );"""

            sql_create_locip_table = """CREATE TABLE IF NOT EXISTS locip (
                                        id integer PRIMARY KEY,
                                        ip_address text NOT NULL,
                                        countrycode text NOT NULL,
                                        countryname text NOT NULL,
                                        city text NOT NULL
                                    );"""

            sql_create_shodan_table = """CREATE TABLE IF NOT EXISTS shodan (
                                        id integer PRIMARY KEY,
                                        ip_address text NOT NULL,
                                        scan_date text NOT NULL,
                                        scan_time text NOT NULL,
                                        record text NOT NULL
                                    );"""

            logging.info("Creating logs table")
            createTable(conn, sql_create_logs_table)
            logging.info("Creating targets table")
            createTable(conn, sql_create_targets_table)
            logging.info("Creating whois table")
            createTable(conn, sql_create_whois_table)
            logging.info("Creating IP location table")
            createTable(conn, sql_create_locip_table)
            logging.info("Creating shodan table")
            createTable(conn, sql_create_shodan_table)
            logging.info("Database initialization complete with SUCCESS")
        
        logging.info("Parsing log file into database")
        with open(logfile, "r") as file:
            count = 1
            for line in file:
                if "Found" in line or "Ban" in line or "Unban" in line:
                    logTab = line.split()                
                    log_date = logTab[0]
                    log_time = logTab[1].split(',')[0]
                    log_action = logTab[6]
                    log_ip = logTab[7]
                    if "Found" in line:
                        find_date = logTab[9] 
                        find_time = logTab[10] 
                    else:
                        find_date = log_date
                        find_time = log_time
                    val = (log_date, log_time, log_action, log_ip, find_date, find_time)              
                    logging.debug("Inserting row #" + str(count) + " : " + str(val))
                    insertLog(conn, val)
                    count += 1
        logging.info("The logs table is now full with " + str(count) + "  log entries")
        logging.debug("Populating the targets table...")
        populateTargets(dbfile)
        logging.info("The targets table is now populated. Check it with -l")
    else:
        logging.info("Something bad happened when creating the database")
    return conn

def getEverythingForTarget(dbfile, target):
    conn = createConnection(dbfile)
    c = conn.cursor()
    c.execute("SELECT * FROM targets WHERE ip_address LIKE '" + target + "'")
    rows = c.fetchall()
    return rows

def getAllTargets(dbfile):
    conn = createConnection(dbfile)
    c = conn.cursor()
    c.execute("SELECT id, ip_address FROM targets")
    rows = c.fetchall()
    return rows

def populateTargets(dbfile):
    conn = createConnection(dbfile)
    c = conn.cursor()
    c.execute("SELECT id, ip_address FROM logs WHERE action = 'Ban'")
    rows = c.fetchall()
    
    for r in rows:
        c.execute("SELECT id FROM targets WHERE ip_address LIKE '" + str(r[1]) + "'")
        temp = c.fetchall()
        if len(temp) == 0:
            c.execute("INSERT INTO targets(ip_address) VALUES('" + r[1] + "')")
            conn.commit()
            logging.debug("Added " + str(r[1]) + " to the targets table")

def getAllLogs(dbfile, target):
    conn = createConnection(dbfile)
    c = conn.cursor()
    c.execute("SELECT * FROM logs WHERE ip_address = '"+target+"'")
    rows = c.fetchall()
    return rows

def designateTarget(dbfile, id):
    conn = createConnection(dbfile)
    c = conn.cursor()
    c.execute("SELECT ip_address FROM targets WHERE id = " + str(id))
    rows = c.fetchall()
    return rows

def getWhois(dbfile, ip):
    conn = createConnection(dbfile)
    c = conn.cursor()
    c.execute("SELECT id, scan_date, scan_time FROM whois WHERE ip_address LIKE '" + str(ip) + "'")
    rows = c.fetchall()
    return rows

def logWhois(dbfile, target):
    now = str(datetime.now())
    today = now.split(" ")[0]
    timeNow = now.split(" ")[1].split(".")[0]
    rec = base64.b64encode(str.encode(whois.whois(target).text)).decode()
    sql = "INSERT INTO whois(ip_address,scan_date,scan_time,record) VALUES('" + target + "','" + today + "','" + timeNow + "','" + rec + "')"
    conn = createConnection(dbfile)
    cur = conn.cursor()
    cur.execute(sql)
    conn.commit()
    sql = "UPDATE targets SET last_whois = '" + rec + "' WHERE ip_address LIKE '" + target + "'"
    cur.execute(sql)
    conn.commit()
    return cur.lastrowid

def getSingleWhois(dbfile,reportid):
    conn = createConnection(dbfile)
    c = conn.cursor()
    c.execute("SELECT record FROM whois WHERE id LIKE '" + str(reportid) + "'")
    rows = c.fetchall()
    return rows

def getGeoIP(dbfile, ip):
    conn = createConnection(dbfile)
    c = conn.cursor()
    c.execute("SELECT id FROM locip WHERE ip_address LIKE '" + str(ip) + "'")
    rows = c.fetchall()
    return rows

def getSingleGeoIP(dbfile,reportid):
    conn = createConnection(dbfile)
    c = conn.cursor()
    c.execute("SELECT countrycode,countryname,city FROM locip WHERE id LIKE '" + str(reportid) + "'")
    rows = c.fetchall()
    return rows

def setGeoIP(dbfile,target):
    gi = GeoIP.open("GeoIPCity.dat", GeoIP.GEOIP_STANDARD)
    gir = gi.record_by_addr(target)

    if gir is not None:
        countrycode = str(gir['country_code'])
        countryname = str(gir['country_name'])
        city =  str(gir['city'])

        sql = "INSERT INTO locip(ip_address,countrycode,countryname,city) VALUES('" + target + "','" + countrycode + "','" + countryname + "','" + city + "')"
        conn = createConnection(dbfile)
        cur = conn.cursor()
        cur.execute(sql)
        conn.commit()
        rec = countrycode + ", " + countryname + ", " + city
        sql = "UPDATE targets SET last_location = '" + rec + "' WHERE ip_address LIKE '" + target + "'"
        cur.execute(sql)
        conn.commit()
        return cur.lastrowid

def getShodan(dbfile, ip):
    conn = createConnection(dbfile)
    c = conn.cursor()
    c.execute("SELECT id, scan_date, scan_time FROM shodan WHERE ip_address LIKE '" + str(ip) + "'")
    rows = c.fetchall()
    return rows

def shodanSearch(query, apikey):
    api = shodan.Shodan(apikey)
    result = api.search(query)
    total = result['total'] 
    matches = result['matches']
    superString = "[I] Number of results : " + str(total) + "\n"
    for service in result['matches']:
            headStr = "# [I] IP address : " + str(service['ip_str']) + " #\n"
            superString += "#" * len(headStr) + "\n" + headStr + "#" * len(headStr) + "\n"
            superString += "[I] ASN : " + str(service['asn']) + "\n" + "[I] ISP : " + str(service['isp'])  + "\n" + "[I] Organization : " + str(service['org']) + "\n"
            for d in service['domains']:
                    superString += "[I] Domain : " + str(d) + "\n"                
            for h in service['hostnames']:
                    superString += "[I] Hostname : " + str(h) + "\n"        
            superString += "[I] OS : " + str(service['os']) + "\n"
            superString += "[I] Transport protocol : " + str(service['transport']) + "\n"
            superString += "[I] Port : " + str(service['port']) + "\n"
            superString += "[I] Data : " + str(service['data']) + "\n"        
            loc = service['location']
            superString += "[I] City : " + str(loc['city']) + "\n"
            superString += "[I] Region : " + str(loc['region_code']) + "\n"
            superString += "[I] Country : " + str(loc['country_name']) + "\n"
            superString += "[I] Country code : " + str(loc['country_code']) + "\n"
            superString += "[I] Longitude : " + str(loc['longitude']) + "\n"
            superString += "[I] Latitude : " + str(loc['latitude']) + "\n"

    return superString

def logShodan(dbfile, target):
    now = str(datetime.now())
    today = now.split(" ")[0]
    timeNow = now.split(" ")[1].split(".")[0]
    
    rec = base64.b64encode(str.encode(shodanSearch(target, SHODAN_API_KEY))).decode()
    
    sql = "INSERT INTO shodan(ip_address,scan_date,scan_time,record) VALUES('" + target + "','" + today + "','" + timeNow + "','" + rec + "')"
    conn = createConnection(dbfile)
    cur = conn.cursor()
    cur.execute(sql)
    conn.commit()
    sql = "UPDATE targets SET last_shodan = '" + rec + "' WHERE ip_address LIKE '" + target + "'"
    cur.execute(sql)
    conn.commit()
    return cur.lastrowid

def getSingleShodan(dbfile,reportid):
    conn = createConnection(dbfile)
    c = conn.cursor()
    c.execute("SELECT record FROM shodan WHERE id LIKE '" + str(reportid) + "'")
    rows = c.fetchall()
    return rows

def main():
    parser = argparse.ArgumentParser(description='Hackback will run information gathering (osint) against IP addresses that are banned in your fail2ban.log log file. It requires your machine to be protected by Fail2ban.')
    parser.add_argument('-a', '--allLogs',     action='store_true', help='Fetch all logs regarding a target in the database (need to provide the target id using the -t argument)',      default=False)
    parser.add_argument('-d', '--database',    type=str,            help='The database file to create. ./hackback.db is the default')
    parser.add_argument('-e', '--logsfile',    type=str,            help='The log file to populate the database, use it with -i or keep ./fail2ban.log as default')
    parser.add_argument('-f', '--force',       action='store_true', help='Force the action to be launched (new attack) even if already present in the database',                         default=False)
    parser.add_argument('-g', '--geoip',       action='store_true', help='Fetch GeoIP information against the target in the database (need to provide the target id)',                   default=False)
    parser.add_argument('-i', '--init',        action='store_true', help='Initialize de database and imports the log file',                                                              default=False)
    parser.add_argument('-l', '--listTargets', action='store_true', help='List the targets in the database',                                                                             default=False)
    parser.add_argument('-r', '--report',      type=int,            help='The report id for the desired action on the desired target')
    parser.add_argument('-s', '--shodan',      action='store_true', help='Fetch shodan information against the target in the database (need to provide the target id)',                  default=False)
    parser.add_argument('-t', '--target',      type=int,            help='The target id for the desired action')
    parser.add_argument('-v', '--verbose',     action='store_true', help='Enable verbose output',                                                                                        default=False)
    parser.add_argument('-w', '--whois',       action='store_true', help='Fetch whois information against the target in the database (need to provide the target id)',                   default=False)
    parser.add_argument('-x', '--allActions',  action='store_true', help='Fetch geoip, shodan and whois information against the target in the database (need to provide the target id)', default=False)
    
    if len(sys.argv) < 2:
        parser.print_help()
        return

    args = parser.parse_args()
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format='[%(asctime)s.%(msecs)03d]  %(message)s', datefmt="%Y-%m-%d %H:%M:%S")
    logging.debug("Verbose mode activated")

    if args.logsfile is not None:
        logfile = args.logsfile
    else:
        logfile = "./fail2ban.log"

    if args.database is not None:
        dbfile = args.database
    else:
        dbfile = "hackback.db"
       
    if args.init:        
        logging.info("Initiating database")
        initdb(dbfile, logfile, args.force) 
    elif exists(dbfile) is False: 
        logging.info("There is no database file, run the initialization first with the -i argument")
    elif args.listTargets:
        logging.debug("You choose to list targets in the database")
        r = getAllTargets(dbfile)
        for l in r:
            logging.info("Target ID : [" + str(l[0]) + "]" + " - IP address : " + l[1])
        logging.debug("Now, select your target with the -t argument ; read the help (-h) to have a full list of possible actions")
    elif args.target:
        t = designateTarget(dbfile, args.target)
        if len(t) == 0:
            logging.info("The target id you entered is not present in the database")
            return
        target = t[0][0]
        logging.debug("Your target is " + target)
        if args.whois:
            if args.force:
                logging.debug("You choose to perform a whois scan on " + target)
                logWhois(dbfile,target)
            elif args.report:
                logging.debug("You choose to view the whois report #" + str(args.report))
                r = getSingleWhois(dbfile, str(args.report))
                if len(r) == 0:
                    logging.info("There is no whois report with id " + str(args.report))
                else:
                    logging.info(base64.b64decode(str.encode(r[0][0])).decode())
            else:
                logging.debug("You choose to check whois for " + target)
                r = getWhois(dbfile, target)
                if len(r) == 0:
                    logging.info("There is no whois entry for " + target + ". Run with -f argument to add an entry.")
                else:
                    logging.info("Run with the -r argument to view a scan report in details")
                    for l in r:
                        logging.info("Scan ID : [" + str(l[0]) + "] - Scan date : " + str(l[1]) + " - Scan time : " + str(l[2]))
        elif args.geoip:
            if args.force:
                logging.debug("You choose to perform a GeoIP scan on " + target)
                
                r = getGeoIP(dbfile, target)
                if len(r) == 0:
                    setGeoIP(dbfile,target)            
                else:
                    logging.info("There is already a GeoIP entry for " + target + ". Use the '-r 1' option to view it.")
            elif args.report:
                logging.debug("You choose to view the GeoIP report #" + str(args.report))
                r = getSingleGeoIP(dbfile, str(args.report))
                if len(r) == 0:
                    logging.info("There is no GeoIP report with id " + str(args.report))
                else:
                    logging.info("IP address   : " + target)
                    logging.info("Country code : " + r[0][0])
                    logging.info("Country name : " + r[0][1])
                    logging.info("City         : " + r[0][2])
            else:
                logging.debug("You choose to check GeoIP for " + target)
                r = getGeoIP(dbfile, target)
                if len(r) == 0:
                    logging.info("There is no GeoIP entry for " + target + ". Run with -f argument to add an entry.")
                else:
                    logging.info("Run with the -r argument to view a scan report in details")
                    for l in r:
                        logging.info("Scan ID : [" + str(l[0]) + "]")
        elif args.shodan:
            if args.force:
                logging.debug("You choose to perform a shodan scan on " + target)
                logShodan(dbfile,target)
            elif args.report:
                logging.debug("You choose to view the shodan report #" + str(args.report))
                r = getSingleShodan(dbfile, str(args.report))
                if len(r) == 0:
                    logging.info("There is no shodan report with id " + str(args.report))
                else:
                    logging.info(base64.b64decode(str.encode(r[0][0])).decode())
            else:
                logging.debug("You choose to check shodan for " + target)
                r = getShodan(dbfile, target)
                if len(r) == 0:
                    logging.info("There is no shodan entry for " + target + ". Run with -f argument to add an entry.")
                else:
                    logging.info("Run with the -r argument to view a scan report in details")
                    for l in r:
                        logging.info("Scan ID : [" + str(l[0]) + "] - Scan date : " + str(l[1]) + " - Scan time : " + str(l[2]))
        elif args.allLogs:
            logging.debug("Finding all logs for " + target)
            r = getAllLogs(dbfile, target)
            for l in r:
                logging.info("Date : "+l[1]+" | Time : "+l[2]+" | Action : "+l[3])
        elif args.allActions:
            if args.force:
                logging.debug("You choose to run all actions on " + target)
                logging.debug("Whois...")
                logWhois(dbfile,target)
                logging.debug("GeoIP...")
                setGeoIP(dbfile,target)  
                logging.debug("Shodan...")
                logShodan(dbfile,target)
                logging.info("Done, you can check the database entries.")
            else:
                logging.debug("You choose to get all information on " + target + ". Run with -f to perform all the actions at once.")
                r = getEverythingForTarget(dbfile, target)
                logging.info("[" + str(r[0][0]) + "] IP address : " + str(r[0][1]))
                if r[0][2] is not None:
                    logging.info("Whois : " + str(base64.b64decode(str.encode(r[0][2])).decode()))
                else:
                    logging.info("No whois information yet. Run the scan with -w -f")
                if r[0][3] is not None:
                    logging.info("Shodan : " + str(base64.b64decode(str.encode(r[0][3])).decode()))
                else:
                    logging.info("No shodan information yet. Run the scan with -s -f")
                if r[0][4] is not None:
                    logging.info("Location : " + str(r[0][4]))
                else:
                    logging.info("No information yet. Run the scan with -g -f")
    return
if __name__ == '__main__':
    main()
