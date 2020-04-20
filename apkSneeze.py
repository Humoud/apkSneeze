#!/usr/bin/python3

from adb_shell.adb_device import AdbDeviceTcp
from adb_shell.auth.sign_pythonrsa import PythonRSASigner
from subprocess import Popen, PIPE
from fnmatch import fnmatch
from pathlib import Path
from time import sleep
import argparse
import sys
import os
import re


DEFAULT_APP_NAME = "sneezed.apk"
DEFAULT_DATA_DIR = "sneezed_data_dir"
parser = argparse.ArgumentParser()
parser.add_argument('-apk', dest='apk', action='store_true', help='Process an apk file.')
parser.set_defaults(apk=False)
parser.add_argument('-apk_name', default=DEFAULT_APP_NAME, help='Name of the apk file to process.')
parser.add_argument('-apk_dl', dest='apk_dl', action='store_true', help='Download apk file from device. Requires params: pkg_name, device_ip, device_port, adbkey_file.')
parser.set_defaults(apk_dl=False)
parser.add_argument('-data_dir_dl', dest='data_dir_dl', action='store_true', help='Download app data directory from device. Requires params: pkg_name, device_ip, device_port, adbkey_file.')
parser.set_defaults(data_dir_dl=False)
parser.add_argument('-pkg_name', default=None, help='Application Package Name (ex: com.dev.app). This is required if you wish to download the apk file.')
parser.add_argument('-device_ip', default=None, help='IP Address of the testing device.')
parser.add_argument('-device_port', default=5555, help='Port number the testing device is listening on.')
parser.add_argument('-adbkey_file', default=str(Path.home())+'/.android/adbkey', help='Location of the adbkey file (ex: /home/user/.android/adbkey).')
parser.add_argument('-adb_over_wifi', dest='adb_over_wifi', action='store_true', help='Setup adb over wifi automatically. You must provide the IP address of the device and have it connected via USB. You can set a custom port using param device_port.')
parser.set_defaults(adb_over_wifi=False)
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

def get_interesting_strings():
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
    
def get_apk_file(adbkey_path, device_ip, device_port, package_name):
    with open(adbkey_path) as f:
        priv = f.read()
    signer = PythonRSASigner('', priv)
    device = AdbDeviceTcp(device_ip, device_port, default_timeout_s=9.)
    device.connect(rsa_keys=[signer], auth_timeout_s=0.1)

    # Send a shell command
    # apk file (base.apk)
    print("<*> Copying APK file to /data/local/tmp/apkSneeze/base.apk (mobile device)...")
    shell_cmd = "su - root -c '\
	mkdir -p /data/local/tmp/apkSneeze && \
	cp /data/app/{}*/base.apk /data/local/tmp/apkSneeze && \
	chmod 777 /data/local/tmp/apkSneeze/base.apk'".format(package_name)

    device.shell(shell_cmd)
    print("<*> Downloading APK file to {}...".format(DEFAULT_APP_NAME))
    device.pull("/data/local/tmp/apkSneeze/base.apk", DEFAULT_APP_NAME)
    print("<*> Download done, check {}".format(DEFAULT_APP_NAME))
    print("<*> Deleting APK file from /data/local/tmp/apkSneeze/base.apk (mobile device)...")
    device.shell("su - root -c 'rm /data/local/tmp/apkSneeze/base.apk'")

def get_app_data_dir(adbkey_path, device_ip, device_port, package_name):
    with open(adbkey_path) as f:
        priv = f.read()
    signer = PythonRSASigner('', priv)
    device = AdbDeviceTcp(device_ip, device_port, default_timeout_s=9.)
    device.connect(rsa_keys=[signer], auth_timeout_s=0.1)
    # apk file (base.apk)
    print("<*> Copying app data dir to /data/local/tmp/apkSneeze/{} (mobile device)...".format(DEFAULT_DATA_DIR))
    shell_cmd = "su - root -c '\
	mkdir -p /data/local/tmp/apkSneeze && \
	cp -r /data/data/{} /data/local/tmp/apkSneeze/{} && \
	chmod -R 777 /data/local/tmp/apkSneeze/'".format(package_name,DEFAULT_DATA_DIR)

    device.shell(shell_cmd)
    print("<*> Downloading app data dir file to {}...")
    ### doesnt allow pulling directories, will execute adb from terminal directly
    # device.pull("/data/local/tmp/apkSneeze/{}/")
    
    for line in run("adb -s {}:{} pull /data/local/tmp/apkSneeze/{}".format(device_ip,device_port)):
            print("    {}".format(line.decode('utf-8')))
    
    print("<*> Download done, check {} dir".format(DEFAULT_DATA_DIR))
    print("<*> Deleting app data dir from /data/local/tmp/apkSneeze/{} (mobile device)...".format(DEFAULT_DATA_DIR))
    device.shell("su - root -c 'rm -r /data/local/tmp/apkSneeze/{}'".format(DEFAULT_DATA_DIR))

def setup_adb_over_wifi(device_ip, device_port):
    print("Killing adb server")
    for line in run("adb kill-server"):
            print("  > {}".format(line.decode('utf-8')))
    # sometimes the server needs time to restart
    sleep(1)
    print("\nListing attached devices")
    for line in run("adb devices"):
            print("  > {}".format(line.decode('utf-8')))
    print("\nSetting the device to listen on port {}".format(device_port))
    for line in run("adb tcpip {}".format(device_port)):
            print("  > {}".format(line.decode('utf-8')))
    # give the device time to finish
    sleep(1)
    print("\nConnecting to the device...")
    for line in run("adb connect {}:{}".format(device_ip,device_port)):
            print("  > {}".format(line.decode('utf-8')))
    print("\nYou can test if everything is working by seeing if you can get a shell: adb -s {}:{} shell".format(device_ip, device_port))


if __name__ == "__main__":
    logo = '''
===========================================================
  ___  ______ _   __  _____ _   _  _____ _____ ______ _____ 
 / _ \ | ___ \ | / / /  ___| \ | ||  ___|  ___|___  /|  ___|
/ /_\ \| |_/ / |/ /  \ `--.|  \| || |__ | |__    / / | |__  
|  _  ||  __/|    \   `--. \ . ` ||  __||  __|  / /  |  __| 
| | | || |   | |\  \ /\__/ / |\  || |___| |___./ /___| |___ 
\_| |_/\_|   \_| \_/ \____/\_| \_/\____/\____/\_____/\____/

v2.0.0
============================================================
    '''
    print(logo)
    
    print("Using Settings:\n\
        +> Process apk file: {}\n\
            > Target apk file name: {}\n\n\
        +> Setup ADB over WiFi: {}\n\
        +> Download apk file: {}\n\
        +> Download app data directory: {}\n\
        >> Settings shared for adb setup and apk\data download:\n\
            >> ADBKey file location: {}\n\
            >> Test device IP address: {}\n\
            >> Test device port: {}\n\
            >> Target package name: {}".format(args.apk, args.apk_name, args.adb_over_wifi, args.apk_dl, args.data_dir_dl, args.adbkey_file, args.device_ip, args.device_port, args.pkg_name))

    if args.apk is False and args.apk_dl is False and args.data_dir_dl is False and args.adb_over_wifi is False:
        print("Nothing to do. Please specify some arguments.")
        sys.exit()

    # User confirmation
    user_input = input('Confirm? [y/n] ')
    if user_input.lower() not in ('y', 'yes'):
        sys.exit()

    if args.adb_over_wifi:
        setup_adb_over_wifi(args.device_ip, args.device_port)

    if args.apk_dl:
        get_apk_file(args.adbkey_file,args.device_ip,args.device_port,args.pkg_name)
    
    if args.data_dir_dl:
        get_app_data_dir(args.adbkey_file,args.device_ip,args.device_port,args.pkg_name)

    # process apk file
    if args.apk:
        print("[0] Processing apk file...")

        print("[1] Decompiling the APK file using APKTOOL...")

        for path in run("apktool d {}".format(args.apk_name)):
            print("  > {}".format(path.decode('utf-8')))

        print("[2] Converting APK file to JAR file using dex2jar...")

        for path in run("d2j-dex2jar {}".format(args.apk_name)):
            print("  > {}".format(path))

        get_interesting_strings()
    
    
    print("Done!")

