#!/usr/bin/python3

from subprocess import Popen, PIPE
import argparse
import os
from fnmatch import fnmatch
import re


parser = argparse.ArgumentParser()
parser.add_argument("apk_name", help="name of the apk file")
args = parser.parse_args()
######
### Lists related detecting interesting entries
### When Scanning the APK
# Regex List
REGEX_LIST = [
    # Domains
    '[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}',
    # More Specific Domains check
    '[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.(com|org|net|io|gov|cc|xyz|club|me|biz|cloud)',
    # IPv4
    '([0-9]{1,3}[\.]){3}[0-9]{1,3}',
    'Authorization:'
]
# Strings List
STRINGS_LIST = [
    'http://',
    'https://',
    'admin',
    'pass',
    'cred'
]
# False Positive list (add more entries for fine tuning)
GREP_FP_KEYWORDS = ["apktool\.yml", "Binary file", "META-INF", "android\.", "facebook\.", "crashlytics", "com\.google", "googletagmanager\.com", "dynamic\.IO", "internal\.IO", "\.xml"]
HTTP_FP_KEYWORDS = ["schemas\.android.com","google\.com","www\.apache\.org","creativecommons\.org","github\.com","www\.example\.com","Binary file","google-analytics\.com"]
HTTPS_FP_KEYWORDS = ["github\.com", "googlesyndication\.com", "googleapis\.com", "doubleclick\.net", "googletagmanager\.com", "crashlytics\.com", "google\.com", "www\.example\.com", "Binary file"]
MISC_FP_KEYWORDS = ["\.xml", "\.png", "\.jpg", "\.jpeg", "\.java"]

def run(command):
    process = Popen(command, stdout=PIPE, shell=True)
    while True:
        line = process.stdout.readline().rstrip()
        if not line:
            break
        # return values as the process is executing
        # instead of waiting for the command to end
        # so that we know that the command is being executed properly
        yield line

if __name__ == "__main__":
    logo = '''
===========================================================
  ___  ______ _   __  _____ _   _  _____ _____ ______ _____ 
 / _ \ | ___ \ | / / /  ___| \ | ||  ___|  ___|___  /|  ___|
/ /_\ \| |_/ / |/ /  \ `--.|  \| || |__ | |__    / / | |__  
|  _  ||  __/|    \   `--. \ . ` ||  __||  __|  / /  |  __| 
| | | || |   | |\  \ /\__/ / |\  || |___| |___./ /___| |___ 
\_| |_/\_|   \_| \_/ \____/\_| \_/\____/\____/\_____/\____/

v1.0.0
============================================================
    '''
    print(logo)

    print("[0] Note: This tool requires: apktool and d2j-dex2jar.")

    print("[1] Decompiling the APK file using APKTOOL...")
    
    for path in run("apktool d {}".format(args.apk_name)):
        print("  > {}".format(path.decode('utf-8')))
    
    print("[2] Converting APK file to JAR file using dex2jar...")

    for path in run("d2j-dex2jar {}".format(args.apk_name)):
        print("  > {}".format(path))

    # for "interesting strings" output
    file_name = args.apk_name.replace('.apk', '')
    strings_file_name = "interesting_strings_{}.txt".format(file_name).replace('.apk', '')
    rootdir = "{}/{}".format(os.getcwd(),file_name)
    ##
    print("[3] Searching for interesting strings(outputing to file {})...".format(strings_file_name))
    hits_counter = 0
    # go through regex list
    print("[3] >> Going through RegEx list...")
    with open(strings_file_name, 'a+') as out:
        for entry in REGEX_LIST:
            out.write("Files that contain: {}\n".format(entry))
            print("Hits: {}".format(hits_counter), end="\r")
            for path in run("grep -ERin '{}' {}".format(entry, rootdir)):
                print("Hits: {}".format(hits_counter), end="\r")
                fp_hit = False
                curr_line = path.decode('utf-8')
                fp_hit = False
                # detect false positive
                for fp in GREP_FP_KEYWORDS:
                    if bool(re.match(r".*"+fp+".*", curr_line)):
                        fp_hit = True
                        break
                if fp_hit:
                        continue
                # write result to file
                hits_counter = hits_counter + 1
                out.write('  ' + str(path) + '\n')

    # go through strings list
    print("[3] >> Going through strings list...")
    with open(strings_file_name, 'a+') as out:
        for entry in STRINGS_LIST:
            out.write("Files that contain: {}\n".format(entry))
            print("Hits: {}".format(hits_counter), end="\r")
            for path in run("grep -Rin '{}' {}".format(entry, rootdir)):
                curr_line = path.decode('utf-8')
                fp_hit = False
                # analysing hits
                print("Hits: {}".format(hits_counter), end="\r")
                # remove false positives
                if entry == "http://":
                    # skip for loop iteration, its a false positive
                    for fp in HTTP_FP_KEYWORDS:
                        if bool(re.match(r".*"+fp+".*", curr_line)):
                            fp_hit = True
                            break
                    if fp_hit:
                        continue
                elif entry == "https://":
                    # skip for loop iteration, its a false positive
                    for fp in HTTPS_FP_KEYWORDS:
                        if bool(re.match(r".*"+fp+".*", curr_line)):
                            fp_hit = True
                            break
                    if fp_hit:
                        continue
                else:
                    for fp in MISC_FP_KEYWORDS:
                        if bool(re.match(r".*"+fp+".*", curr_line)):
                            fp_hit = True
                            break
                    if fp_hit:
                        continue
                # write result to file
                hits_counter = hits_counter + 1
                out.write('  ' + str(path) + '\n')

    print("Hits: {}".format(hits_counter))
    print("Done!")
