from subprocess import Popen, PIPE
import argparse
import os
from fnmatch import fnmatch
import re


parser = argparse.ArgumentParser()
parser.add_argument("apk_name", help="name of the apk file")
args = parser.parse_args()

def run(command):
    process = Popen(command, stdout=PIPE, shell=True)
    while True:
        line = process.stdout.readline().rstrip()
        if not line:
            break
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

v0.1.0
============================================================
    '''
    print(logo)

    print("[1] Decompiling the APK file using APKTOOL...")
    
    for path in run("apktool d {}".format(args.apk_name)):
        print(path)
    
    print("[2] Converting APK file to JAR file using dex2jar...")

    for path in run("d2j-dex2jar {}".format(args.apk_name)):
        print(path)

    # for interesting strings output
    file_name = args.apk_name.replace('.apk', '')
    strings_file_name = "interesting_strings_{}.txt".format(file_name).replace('.apk', '')
    rootdir = "{}/{}".format(os.getcwd(),file_name)
    regex_list = [
        '[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}',
        '([0-9]{1,3}[\.]){3}[0-9]{1,3}'
    ]
    strings_list = [
        'http://',
        'https://'
    ]
    ##
    print("[3] Searching for interesting strings(outputing to file {})...".format(strings_file_name))
    hits_counter = 0
    # go through regex list
    print("[3] >> Going through RegEx list...")
    with open(strings_file_name, 'a+') as out:
        for entry in regex_list:
            out.write("Files that contain: {}\n".format(entry))
            print("Hits: {}".format(hits_counter), end="\r")
            for path in run("grep -ERin '{}' {}".format(entry, rootdir)):
                print("Hits: {}".format(hits_counter), end="\r")
                # detect false positive
                if ".xml" in str(path):
                    continue
                if "apktool.yml" in str(path):
                    continue
                if "Binary file" in str(path):
                    continue
                if ".java" in str(path):
                    continue
                if "META-INF" in str(path):
                    continue
                if "android." in str(path):
                    continue
                if "facebook." in str(path):
                    continue
                if "crashlytics" in str(path):
                    continue
                # write result to file
                hits_counter = hits_counter + 1
                out.write('  ' + str(path) + '\n')

    # go through strings list
    print("[3] >> Going through strings list...")
    with open(strings_file_name, 'a+') as out:
        for entry in strings_list:
            out.write("Files that contain: {}\n".format(entry))
            print("Hits: {}".format(hits_counter), end="\r")
            for path in run("grep -Rin '{}' {}".format(entry, rootdir)):
                # analysing hits
                print("Hits: {}".format(hits_counter), end="\r")
                # remove false positives
                if entry == "http://":
                    # skip for loop iteration, its a false positive
                    if "schemas.android.com" in str(path):
                        continue
                    if "google.com" in str(path):
                        continue
                    if "www.apache.org" in str(path):
                        continue
                    if "creativecommons.org" in str(path):
                        continue
                    if "github.com" in str(path):
                        continue
                    if "www.example.com"  in str(path):
                        continue
                    if "Binary file" in str(path):
                        continue
                elif entry == "https://":
                    # skip for loop iteration, its a false positive
                    if "github.com" in str(path):
                        continue
                    if "googlesyndication.com" in str(path):
                        continue
                    if "googleapis.com" in str(path):
                        continue
                    if "doubleclick.net" in str(path):
                        continue
                    if "googletagmanager.com" in str(path):
                        continue
                    if "crashlytics.com" in str(path):
                        continue
                    if "google.com" in str(path):
                        continue
                    if "www.example.com"  in str(path):
                        continue
                    if "Binary file" in str(path):
                        continue
                # write result to file
                hits_counter = hits_counter + 1
                out.write('  ' + str(path) + '\n')

    print("Hits: {}".format(hits_counter))
    print("Done!")
