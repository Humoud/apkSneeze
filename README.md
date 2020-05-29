# apkSneeze
**v2.0.0**

A tool that automates the mundane tasks of pentesting Android apps.

The tool currently provides the following features:
1. Decompiles the provided apk file.
2. Converts the provided apk file to a Jar file.
3. Searches the decompiled files for interesting strings.
4. Sets up ADB over WiFi.
5. Downloads apk files from a test device (requires a rooted device).
    * The Location on an Android device `/data/app/`
6. Downloads app data directories from a test device (requires a rooted device).
    * The location on an Android device `/data/data`

You can chain modes of operation to automate your own custom workflow.

Example:
* Setup ADB over WiFi > Download an APK file > Decompile it.
* Download an APK file > Download app data directory > Decompile an unrelated apk file.
* Setup ADB over WiFi >  Decompile apk file.
* Just decompile an apk file.


```shell
humoud@komputer:~/Documents/dev/apkSneeze# python3 apkSneeze.py -adb_over_wifi -device_ip 192.168.1.114 -apk_dl -pkg_name com.dev.test.example -apk

===========================================================
  ___  ______ _   __  _____ _   _  _____ _____ ______ _____ 
 / _ \ | ___ \ | / / /  ___| \ | ||  ___|  ___|___  /|  ___|
/ /_\ \| |_/ / |/ /  \ `--.|  \| || |__ | |__    / / | |__  
|  _  ||  __/|    \   `--. \ . ` ||  __||  __|  / /  |  __| 
| | | || |   | |\  \ /\__/ / |\  || |___| |___./ /___| |___ 
\_| |_/\_|   \_| \_/ \____/\_| \_/\____/\____/\_____/\____/

v2.0.0
============================================================
    
Using Settings:
        +> Process apk file: True
            > Target apk file name: sneezed.apk

        +> Setup ADB over WiFi: True
        +> Download apk file: True
        +> Download app data directory: False
        >> Settings shared for adb setup and apk\data download:
            >> ADBKey file location: /home/humoud/.android/adbkey
            >> Test device IP address: 192.168.1.114
            >> Test device port: 5555
            >> Target package name: com.dev.test.example
Confirm? [y/n] y
Killing adb server

Listing attached devices
* daemon not running; starting now at tcp:5037
* daemon started successfully
  > List of devices attached
  > xxxxx	device

Setting the device to listen on port 5555
  > restarting in TCP mode port: 5555

Connecting to the device...
  > connected to 192.168.1.114:5555

You can test if everything is working by seeing if you can get a shell: adb -s 192.168.1.114:5555 shell
<*> Copying APK file to /data/local/tmp/apkSneeze/base.apk (mobile device)...
<*> Downloading APK file to sneezed.apk...
<*> Download done, check sneezed.apk
<*> Deleting APK file from /data/local/tmp/apkSneeze/base.apk (mobile device)...
[0] Processing apk file...
[1] Decompiling the APK file using APKTOOL...
  > I: Using Apktool 2.4.0-dirty on sneezed.apk
  > I: Loading resource table...
  > I: Decoding AndroidManifest.xml with resources...
  > I: Loading resource table from file: /home/humoud/.local/share/apktool/framework/1.apk
  > I: Regular manifest package...
  > I: Decoding file-resources...
  > I: Decoding values */* XMLs...
  > I: Baksmaling classes.dex...
  > I: Baksmaling classes2.dex...
  > I: Baksmaling classes3.dex...
  > I: Copying assets and libs...
  > I: Copying unknown files...
  > I: Copying original files...
[2] Converting APK file to JAR file using dex2jar...
dex2jar sneezed.apk -> ./sneezed-dex2jar.jar
[3] Searching for interesting strings(outputing to file interesting_strings_sneezed.txt)...
[3] >> Going through RegEx list...
[3] >> Going through strings list...
Hits: 20853
Done!

```

Requirements:
1. Linux (the tool uses grep)
2. apktool
3. dex2jar
4. adb_shell (use requirements.txt to download it)


### Install Requirements.txt
`python3 -m pip install -r requirements.txt`

Note: The tool was tested and developed on Kali linux it has apktool and dex2jar installed.

### Usage:

#### Process apk file
To process an apk file (Decompile, convert to Jar, and scan for interesting strings):

`python3 apkSneeze.py -apk -apk_name test.apk`

#### Setup ADB over WiFi
To setup ADB over WiFi, device must be connected via USB:

`python3 apkSneeze.py -adb_over_wifi -device_ip 192.168.1.114`

Set a custom port:

`python3 apkSneeze.py -adb_over_wifi -device_ip 192.168.1.114 -device_port 10111`

#### Download APK File

To download an apk file from a test device (root access required):

`python3 apkSneeze.py -apk_dl -pkg_name com.dev.test -device_ip 192.168.1.114`

If you are using a port other than 5555 (custom port):

`python3 apkSneeze.py -apk_dl -pkg_name com.dev.test -device_ip 192.168.1.114 -device_port 10111`


#### Download an App's Data Directory

To download an app's data directory (/data/data) from a test device (root access required):

`python3 apkSneeze.py -data_dir_dl -device_ip 192.168.1.114 -pkg_name com.test.target.app`

#### Chain

You can chain operation modes. Ex: setup adb over wifi, the download an apk file, and finally process the downloaded apk file.
`python3 apkSneeze.py -adb_over_wifi -device_ip 192.168.1.114 -apk_dl -pkg_name com.dev.test.example -apk`

#### Defaults
The tools defaults to the following:
* location of ADBKey: ~/.android/adbkey
* app name: sneezed.apk
* adb port: 5555

They can all be changed by specifying the appropriate parameter.

```shell
usage: apkSneeze.py [-h] [-apk] [-apk_name APK_NAME] [-apk_dl] [-data_dir_dl]
                    [-pkg_name PKG_NAME] [-device_ip DEVICE_IP]
                    [-device_port DEVICE_PORT] [-adbkey_file ADBKEY_FILE]
                    [-adb_over_wifi]

optional arguments:
  -h, --help            show this help message and exit
  -apk                  Process an apk file.
  -apk_name APK_NAME    Name of the apk file to process.
  -apk_dl               Download apk file from device. Requires params:
                        pkg_name, device_ip, device_port, adbkey_file.
  -data_dir_dl          Download app data directory from device. Requires
                        params: pkg_name, device_ip, device_port, adbkey_file.
  -pkg_name PKG_NAME    Application Package Name (ex: com.dev.app). This is
                        required if you wish to download the apk file.
  -device_ip DEVICE_IP  IP Address of the testing device.
  -device_port DEVICE_PORT
                        Port number the testing device is listening on.
  -adbkey_file ADBKEY_FILE
                        Location of the adbkey file (ex:
                        /home/user/.android/adbkey).
  -adb_over_wifi        Setup adb over wifi automatically. You must provide
                        the IP address of the device and have it connected via
                        USB. You can set a custom port using param
                        device_port.
```

## Legal Disclaimer
Usage of APKSneeze for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.
