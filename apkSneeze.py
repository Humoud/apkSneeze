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

v0.0.1
============================================================
    '''
    print(logo)

    print("[1] Decompiling the APK file using APKTOOL...")
    
    for path in run("apktool d {}".format(args.apk_name)):
        print(path)
    
    print("[2] Converting APK file to JAR file using dex2jar...")

    for path in run("d2j-dex2jar {}".format(args.apk_name)):
        print(path)


    print("[3] Searching for interesting strings(outputing to file interesting_strings.txt)...")
    file_name = args.apk_name.replace('.apk', '')
    rootdir = "{}/{}".format(os.getcwd(),file_name)
    pattern = "/(?:\d{1,3}\.){3}\d{1,3}/"
    p = re.compile(pattern)
    strings_list = [
        '[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}',
        '(?:\d{1,3}\.){3}\d{1,3}',
        'private',
        'public',
        'key',
        'token',
        'root',
        'rooted',
        'detection',
        'http://',
        'https://',
        'RSA',
        'DB',
        'database',
        'sql'
    ]
    hits_counter = 0
    with open('interesting_strings.txt', 'w+') as out:
        for entry in strings_list:
            out.write("Files that contain: {}\n".format(entry))
            print ("Hits: {}".format(hits_counter), end="\r")
            for path in run("grep -Ri '{}' {}".format(entry, rootdir)):
                #print(path)
                hits_counter = hits_counter + 1
                print ("Hits: {}".format(hits_counter), end="\r")
                out.write('  ' + str(path) + '\n')

    #for path, subdirs, files in os.walk(rootdir):
    #    for name in files:
            #if fnmatch(name, pattern):
    #        target_file = os.path.join(path, name)
    print ("Hits: {}".format(hits_counter))
    print("Done!")
