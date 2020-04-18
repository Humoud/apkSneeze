# apkSneeze
**v1.0.0**

A tool that automates the mundane tasks of pentesting Android apps. It uses APKTool and Dex2Jar.

The tool currently:
1. Decompiles the provided apk file.
2. Converts the provided apk file to a Jar file.
3. Searches the decompiled files for interesting strings.

Requirements:
1. Linux (the tool uses grep)
2. apktool
3. dex2jar

Note that the tool was tested and developed on Kali Linux. Kali has all the required dependencies.

Usage:

`python3 apkSneeze.py apk_file_name.apk`
