# Android Penetration Testing Cheat Sheet

This is more of a checklist for myself. May contain useful tips and tricks.

**Still a lot of things to add.**

Everything was tested on Kali Linux v2022.2 (64-bit) and Samsung A5 (2017) with Android OS v8.0 (Oreo) and Magisk root v25.2.

Check [Magisk](https://topjohnwu.github.io/Magisk) if you want to root your Android device. I have no [liability](https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/blob/main/LICENSE) over your actions.

For help with any of the tools type `<tool_name> [-h | -hh | --help]` or `man <tool_name>`.

If you didn't already, read [OWASP MSTG](https://github.com/OWASP/owasp-mastg) and [OWASP MASVS](https://github.com/OWASP/owasp-masvs). You can download OWASP MSTG checklist from [here](https://github.com/OWASP/owasp-mastg/releases).

Highly recommend reading [HackTricks - Android Applications Pentesting](https://book.hacktricks.xyz/mobile-pentesting/android-app-pentesting).

Websites that you should use while writing the report:

* [cwe.mitre.org/data](https://cwe.mitre.org/data)
* [owasp.org/projects](https://owasp.org/projects)
* [owasp.org/www-project-mobile-top-10](https://owasp.org/www-project-mobile-top-10)
* [cheatsheetseries.owasp.org](https://cheatsheetseries.owasp.org/Glossary.html)
* [nvd.nist.gov/vuln-metrics/cvss/v3-calculator](https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator)
* [nvd.nist.gov/ncp/repository](https://nvd.nist.gov/ncp/repository)
* [attack.mitre.org](https://attack.mitre.org)

My other cheat sheets:

* [iOS Testing Cheat Sheet](https://github.com/ivan-sincek/ios-penetration-testing-cheat-sheet)
* [Penetration Testing Cheat Sheet](https://github.com/ivan-sincek/penetration-testing-cheat-sheet)
* [WiFi Penetration Testing Cheat Sheet](https://github.com/ivan-sincek/wifi-penetration-testing-cheat-sheet)

## Table of Contents

**0. [Install Tools](#0-install-tools)**

* [WiFi ADB - Debug Over Air](#wifi-adb---debug-over-air)
* [Magisk Frida](#magisk-frida)
* [Magisk SQLite 3](#magisk-sqlite-3)
* [Kali Linux Tools](#kali-linux-tools)
* [Apktool](#apktool)
* [Mobile Security Framework (MobSF)](#mobile-security-framework-mobsf)
* [Drozer](#drozer)

**1. [Basics](#1-basics)**

* [Android Debug Bridge (ADB)](#android-debug-bridge-adb)
* [Install/Uninstall an APK](#installuninstall-an-apk)
* [Pull an APK (base.apk)](#pull-an-apk-baseapk)
* [Open a System Shell](#open-a-system-shell)
* [Download/Upload Files and Directories](#downloadupload-files-and-directories)
	* [Bypassing Permission Denied](#bypassing-permission-denied)

**3. [Search for Files and Directories](#3-search-for-files-and-directories)**

**4. [Inspect Files](#4-inspect-files)**

* [Single File](#single-file)
* [Multiple Files](#multiple-files)
* [SQLite 3](#sqlite-3)
* [Backups](#backups)

**5. [Deeplinks](#5-deeplinks)**

**6. [Frida](#6-frida)**

* [Frida Scripts](#frida-scripts)

**7. [Objection](#7-objection)**

* [Bypasses](#bypasses)

**8. [Drozer](#8-drozer)**

* [Activities](#activities)
* [Providers](#providers)

**9. [Decompile an APK](#9-decompile-an-apk)**

**10. [Repackage an APK](#10-repackage-an-apk)**

**11. [Tips and Security Best Practices](#11-tips-and-security-best-practices)**

**12. [Useful Websites and Tools](#12-useful-websites-and-tools)**

## 0. Install Tools

### WiFi ADB - Debug Over Air

Install [WiFi ADB - Debug Over Air](https://play.google.com/store/apps/details?id=com.ttxapps.wifiadb). To be used with [ADB](#android-debug-bridge-adb).

<p align="center"><img src="https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/blob/main/img/wifi_adb.jpg" alt="WiFi ADB - Debug Over Air" height="600em"></p>

<p align="center">Figure 1 - WiFi ADB - Debug Over Air</p>

### Magisk Frida

Download [Magisk Frida](https://github.com/ViRb3/magisk-frida/releases), then, open your [Magisk](https://topjohnwu.github.io/Magisk) app and install Frida by importing the downloaded archive.

<p align="center"><img src="https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/blob/main/img/magisk_install_from_storage.jpg" alt="Magisk Frida" height="600em"></p>

<p align="center">Figure 2 - Magisk Frida</p>

### Magisk SQLite 3

Download [Magisk SQLite 3](https://github.com/stylemessiah/SQLite3UniversalBinaries/tags), then, open your [Magisk](https://topjohnwu.github.io/Magisk) app and install SQLite 3 by importing the downloaded archive.

### Kali Linux Tools

Install required tools on your Kali Linux:

```fundamental
apt-get -y install docker.io

systemctl start docker

apt-get -y install adb dex2jar jadx radare2 sqlite3 sqlitebrowser xmlstarlet

pip3 install frida-tools objection
```

Make sure that Frida and Objection are always up to date:

```fundamental
pip3 install frida-tools objection --upgrade
```

### Apktool

Download and install:

```bash
apt-get -y install aapt

wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O /root/Desktop/apktool

chmod +x /root/Desktop/apktool && cp /root/Desktop/apktool /usr/local/bin/apktool

wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.7.0.jar -O /root/Desktop/apktool.jar

chmod +x /root/Desktop/apktool.jar && cp /root/Desktop/apktool.jar /usr/local/bin/apktool.jar
```

### Mobile Security Framework (MobSF)

Install:

```fundamental
docker pull opensecurity/mobile-security-framework-mobsf
```

Run:

```fundamental
docker run -it --rm --name mobsf -p 8000:8000 opensecurity/mobile-security-framework-mobsf
```

Navigate to `http://localhost:8000` using your preferred web browser.

Uninstall:

```fundamental
docker image rm opensecurity/mobile-security-framework-mobsf
```

### Drozer

Install:

```fundamental
docker pull fsecurelabs/drozer
```

Run:

```fundamental
docker run -it --rm --name drozer fsecurelabs/drozer
```

Download [Drozer Agent](https://github.com/WithSecureLabs/drozer-agent/releases) and install it either manually or by using [ADB](#android-debug-bridge-adb).

Uninstall:

```fundamental
docker image rm fsecurelabs/drozer
```

## 1. Basics

### Android Debug Bridge (ADB)

Start the server:

```fundamental
adb start-server
```

List attached devices:

```fundamental
adb devices
```

Connect to a remote device using [WiFi ADB](#wifi-adb---debug-over-air):

```fundamental
adb connect 192.168.1.10:5555
```

Stop the server:

```fundamental
adb kill-server
```

### Install/Uninstall an APK

Install an APK (specify `-s` to install it to a removable storage):

```fundamental
adb install someapp.apk

adb install -s someapp.apk
```

Uninstall an APK (specify `-k` to keep the data and cache directories):

```fundamental
adb uninstall com.someapp.dev

adb uninstall -k com.someapp.dev
```

### Pull an APK (base.apk)

```bash
adb shell pm list packages 'keyword' | cut -d ':' -f2

adb pull $(adb shell pm path com.someapp.dev | cut -d ':' -f2 | grep 'base.apk') ./
```

```bash
keyword="keyword"; pkg=$(adb shell pm list packages "${keyword}" | cut -d ':' -f2); adb pull $(adb shell pm path "${pkg}" | cut -d ':' -f2 | grep 'base.apk') ./
```

### Open a System Shell

Open a system shell as non-root:

```fundamental
adb shell
```

Open a system shell as root:

```fundamental
adb shell su
```

### Download/Upload Files and Directories

Some of the internal storage paths:

```fundamental
/data/local/tmp/

/data/data/com.someapp.dev/cache/
/data/user/0/com.someapp.dev/cache/

/mnt/sdcard/Android/data/com.someapp.dev/cache/
/storage/emulated/0/Android/data/com.someapp.dev/cache/

/mnt/sdcard/Android/obb/com.someapp.dev/cache/
/storage/emulated/0/Android/obb/com.someapp.dev/cache/

/mnt/media_rw/3664-6132/Android/data/com.someapp.dev/files
/storage/3664-6132/Android/data/com.someapp.dev/files
```

Number `0` in both, `/data/user/0/` and `/storage/emulated/0/` paths, represents the first user in a multi-user device.

Don't confuse `/mnt/sdcard/` path with a real removable storage path because sometimes such path is device specific, so you will need to search it on the internet or extract it using some Java code. In my case it is `/mnt/media_rw/3664-6132/` path.

```fundamental
XML                     -->  Method                                     -->  Path

<files-path/>           -->  getContext().getFilesDir()                 -->  /data/user/0/com.someapp.dev/files

<cache-path/>           -->  getContext().getCacheDir()                 -->  /data/user/0/com.someapp.dev/cache

<external-path/>        -->  Environment.getExternalStorageDirectory()  -->  /storage/emulated/0

<external-files-path/>  -->  getContext().getExternalFilesDir("")       -->  /storage/emulated/0/Android/data/com.someapp.dev/files

<external-cache-path/>  -->  getContext().getExternalCacheDir()         -->  /storage/emulated/0/Android/data/com.someapp.dev/cache

<external-media-path/>  -->  getContext().getExternalMediaDirs()        -->  /storage/emulated/0/Android/media/com.someapp.dev
                                                                             /storage/3664-6132/Android/media/com.someapp.dev
																   
-                       -->  getContext().getExternalFilesDirs("")      -->  /storage/emulated/0/Android/data/com.someapp.dev/files
                                                                             /storage/3664-6132/Android/data/com.someapp.dev/files
```

---

Tilde `~` is short for the root directory.

Download a file or directory from your Android device:

```fundamental
adb pull ~/somefile.txt ./

adb pull ~/somedir ./
```

Keep in mind that some directories do not have the write and/or execute permission; regardless, you can always upload files to and execute from `/data/local/tmp/` directory.

Upload a file or directory to your Android device:

```fundamental
adb push somefile.txt /data/local/tmp/

adb push somedir /data/local/tmp/
```

Empty directory will not be uploaded.

### Bypassing Permission Denied

Download a file from your Android device:

```bash
adb shell su -c 'cat ~/somefile.txt' > somefile.txt

adb shell su -c 'run-as com.someapp.dev cat ~/somefile.txt' > somefile.txt
```

Download a directory from your Android device:

```bash
dir="somedir"; IFS=$'\n'; for subdir in $(adb shell su -c "find \"${dir}\" -type d | sed 's/ /\\\ /g'"); do mkdir -p ".${subdir}"; done; for file in $(adb shell su -c "find \"${dir}\" -type f | sed 's/ /\\\ /g'"); do adb shell su -c "cat \"${file}\"" > ".${file}"; done;
```

Upload a file or directory to your Android device:

```bash
src="somefile.txt"; dst="/data/data/com.someapp.dev/"; tmp="/data/local/tmp/"; base=$(basename "${src}"); adb push "${src}" "${tmp}"; adb shell su -c "cp -r \"${tmp}${base}\" \"${dst}\" && rm -rf \"${tmp}${base}\""
```

## 3. Search for Files and Directories

Search for files and directories from the global root directory:

```bash
find / -iname '*keyword*'
```

Search for files and directories in app specific directories (run `env` in [Objection](#7-objection)):

```bash
cd /data/user/0/com.someapp.dev/

cd /storage/emulated/0/Android/data/com.someapp.dev/

cd /storage/emulated/0/Android/obb/com.someapp.dev/
```

If you want to download a whole directory from your Android device, see section [Download/Upload Files and Directories](#downloadupload-files-and-directories).

Search for files and directories from the current directory:

```bash
find . -iname '*keyword*'

for keyword in 'access' 'account' 'admin' 'card' 'cer' 'conf' 'cred' 'customer' 'email' 'history' 'info' 'json' 'jwt' 'key' 'kyc' 'log' 'otp' 'pass' 'pem' 'pin' 'plist' 'priv' 'refresh' 'salt' 'secret' 'seed' 'setting' 'sign' 'sql' 'token' 'transaction' 'transfer' 'tar' 'txt' 'user' 'zip' 'xml'; do find . -iname "*${keyword}*"; done
```

## 4. Inspect Files

Inspect memory dumps, binaries, files inside [a decompiled APK](#9-decompile-an-apk), or any other files.

After you finish testing, don't forget to download app specific directories using [adb](#downloadupload-files-and-directories) and inspect all the files inside.

There will be some false positive results since the regular expressions are not perfect. I prefer to use `rabin2` over `strings` because it can read Unicode characters.

On your Android device, try to modify app's files to test the filesystem checksum validation, i.e. to test the file integrity validation.

### Single File

Extract hardcoded sensitive data:

```bash
rabin2 -zzzqq somefile | grep -Pi '[^\w\d]+(basic|bearer)\ .+'

rabin2 -zzzqq somefile | grep -Pi '(access|account|admin|basic|bearer|card|conf|cred|customer|email|history|id|info|jwt|key|kyc|log|otp|pass|pin|priv|refresh|salt|secret|seed|setting|sign|token|transaction|transfer|user)\w*(?:\"\ *\:|\ *\=).+'

rabin2 -zzzqq somefile | grep -Pi '([^\w\d]+(to(\_|\ )do|todo|note)\ |\/\/|\/\*|\*\/).+'
```

Extract URLs, deeplinks, IPs, etc.:

```bash
rabin2 -zzzqq somefile | grep -Po '\w+\:\/\/[\w\-\.\@\:\/\?\=\%\&\#]+' | grep -Piv '\.(css|gif|jpeg|jpg|ogg|otf|png|svg|ttf|woff|woff2)' | sort -uf | tee urls.txt

rabin2 -zzzqq somefile | grep -Po '(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}' | sort -uf | tee ips.txt
```

Extract all strings and decode Base64 strings:

```bash
rabin2 -zzzqq somefile | sort -uf > strings.txt

grep -Po '(?:([a-zA-Z0-9\+\/]){4})*(?:(?1){4}|(?1){3}\=|(?1){2}\=\=)' strings.txt | sort -uf > base64.txt

for string in $(cat base64.txt); do res=$(echo "${string}" | base64 -d 2>/dev/null | grep -PI '[\s\S]+'); if [[ ! -z $res ]]; then echo -n "${string}\n${res}\n\n"; fi; done | tee base64_decoded.txt
```

### Multiple Files

Extract hardcoded sensitive data:

```bash
IFS=$'\n'; for file in $(find . -type f); do echo -n "\nFILE: \"${file}\"\n"; rabin2 -zzzqq "${file}" 2>/dev/null | grep -Pi '[^\w\d]+(basic|bearer)\ .+'; done

IFS=$'\n'; for file in $(find . -type f); do echo -n "\nFILE: \"${file}\"\n"; rabin2 -zzzqq "${file}" 2>/dev/null | grep -Pi '(access|account|admin|basic|bearer|card|conf|cred|customer|email|history|id|info|jwt|key|kyc|log|otp|pass|pin|priv|refresh|salt|secret|seed|setting|sign|token|transaction|transfer|user)\w*(?:\"\ *\:|\ *\=).+'; done

IFS=$'\n'; for file in $(find . -type f); do echo -n "\nFILE: \"${file}\"\n"; rabin2 -zzzqq "${file}" 2>/dev/null | grep -Pi '([^\w\d]+(to(\_|\ )do|todo|note)\ |\/\/|\/\*|\*\/).+'; done
```

Extract URLs, deeplinks, IPs, etc.:

```bash
IFS=$'\n'; for file in $(find . -type f); do rabin2 -zzzqq "${file}" 2>/dev/null; done | grep -Po '\w+\:\/\/[\w\-\.\@\:\/\?\=\%\&\#]+' | grep -Piv '\.(css|gif|jpeg|jpg|ogg|otf|png|svg|ttf|woff|woff2)' | sort -uf | tee urls.txt

IFS=$'\n'; for file in $(find . -type f); do rabin2 -zzzqq "${file}" 2>/dev/null; done | grep -Po '(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}' | sort -uf | tee ips.txt
```

Extract all strings and decode Base64 strings:

```bash
IFS=$'\n'; for file in $(find . -type f); do rabin2 -zzzqq "${file}" 2>/dev/null; done | sort -uf > strings.txt

grep -Po '(?:([a-zA-Z0-9\+\/]){4})*(?:(?1){4}|(?1){3}\=|(?1){2}\=\=)' strings.txt | sort -uf > base64.txt

for string in $(cat base64.txt); do res=$(echo "${string}" | base64 -d 2>/dev/null | grep -PI '[\s\S]+'); if [[ ! -z $res ]]; then echo -n "${string}\n${res}\n\n"; fi; done | tee base64_decoded.txt
```

### SQLite 3

Use [adb](#downloadupload-files-and-directories) to download database files. Once downloaded, open them with [DB Browser for SQLite](https://sqlitebrowser.org).

To inspect the content, navigate to `Browse Data` tab, expand `Table` dropdown menu, and select the desired table.

<p align="center"><img src="https://github.com/ivan-sincek/android-penetration-testing-cheat-sheet/blob/main/img/sqlite.png" alt="SQLite"></p>

<p align="center">Figure 3 - DB Browser for SQLite</p>

To inspect and/or edit database files on your Android device directly, use [SQLite 3](#magisk-sqlite-3); [adb](#android-debug-bridge-adb) to your Android device and run the following commands:

```sql
sqlite3 somefile

.dump

.tables

SELECT * FROM sometable;

.quit
```

### Backups

Create a backup:

```fundamental
adb backup -system -apk -shared -all -f backup.ab
```

Download the latest [Android Backup Extrator](https://github.com/nelenkov/android-backup-extractor/releases), and repack a backup:

```fundamental
java -jar abe.jar unpack backup.ab backup.tar

java -jar abe.jar pack backup.tar backup.ab
```

Restore a backup:

```fundamental
adb restore backup.ab
```

## 5. Deeplinks

To do.

## 6. Frida

Useful resources:

* [frida.re](https://frida.re/docs/home)
* [learnfrida.info](https://learnfrida.info)
* [codeshare.frida.re](https://codeshare.frida.re)
* [github.com/dweinstein/awesome-frida](https://github.com/dweinstein/awesome-frida)
* [github.com/interference-security/frida-scripts](https://github.com/interference-security/frida-scripts)
* [github.com/m0bilesecurity/Frida-Mobile-Scripts](https://github.com/m0bilesecurity/Frida-Mobile-Scripts)
* [github.com/WithSecureLabs/android-keystore-audit](https://github.com/WithSecureLabs/android-keystore-audit)

List processes:

```bash
frida-ps -Uai

frida-ps -Uai | grep -i 'keyword'
```

Get PID for a specified keyword:

```bash
frida-ps -Uai | grep -i 'keyword' | cut -d ' ' -f 1
```

Discover internal methods/calls:

```bash
frida-discover -U -f com.someapp.dev | tee frida_discover.txt
```

Trace internal methods/calls:

```bash
frida-trace -U -p 1337

frida-trace -U -p 1337 -i 'recv*' -i 'send*'
```

### Frida Scripts

Bypass SSL Pinning using [android-ssl-pinning-bypass](https://codeshare.frida.re/@ivan-sincek/android-ssl-pinning-bypass) script:

```fundamental
frida -U -no-pause -l android-ssl-pinning-bypass.js -f com.someapp.dev

frida -U -no-pause --codeshare ivan-sincek/android-ssl-pinning-bypass -f com.someapp.dev
```

I prefer to use the built-in method in [Objection](#bypasses).

## 7. Objection

Useful resources:

* [github.com/sensepost/objection](https://github.com/sensepost/objection)

Run:

```fundamental
objection -g com.someapp.dev explore
```

Run a [Frida](#6-frida) script in Objection:

```fundamental
import somescript.js

objection -g com.someapp.dev explore --startup-script somescript.js
```

Get environment variables:

```fundamental
env
```

List KeyStore:

```fundamental
android keystore list
```

Dump app's memory to a file:

```fundamental
memory dump all mem.dmp
```

Dump app's memory after e.g. 10 minutes of inactivity, then, check if sensitive data is still in the memory. See section [4. Inspect Files](#4-inspect-files).

Search app's memory directly:

```fundamental
memory search 'somestring' --string
```

List classes and methods:

```bash
android hooking list classes
android hooking search classes 'keyword'

android hooking list class_methods 'someclass'
android hooking search methods 'keyword'
```

Hook on a class or method:

```bash
android hooking watch class 'someclass'

android hooking watch method '-[someclass somemethod]' --dump-args --dump-backtrace --dump-return
```

Change the method's return value:

```bash
android hooking set return_value '-[someclass somemethod]' false
```

Monitor the clipboard:

```fundamental
android clipboard monitor
```

### Bypasses

Bypass a root detection:

```bash
android root disable --quiet

objection -g com.someapp.dev explore --startup-command 'android root disable --quiet'
```

---

Bypass SSL pinning:

```bash
android sslpinning disable --quiet

objection -g com.someapp.dev explore --startup-command 'android sslpinning disable --quiet'
```

Also, you can import [Frida](#frida-scripts) script.

## 8. Drozer

Connect to a remote agent:

```fundamental
drozer console connect --server 192.168.1.10
```

List modules and show module details:

```fundamental
list

run somemodule --help
```

Open a system shell as non-root:

```fundamental
shell
```

---

List packages:

```fundamental
run app.package.list

run app.package.list -f 'keyword'

run app.package.backup

run app.package.debuggable
```

Show a package information:

```fundamental
run app.package.info -a com.someapp.dev
```

Show app's AndroidManifest.xml:

```fundamental
run app.package.manifest com.someapp.dev
```

In case you cannot see the whole manifest, decode the APK using [Apktool](#apktool) and just open the file manually.

Show app's attack surface:

```fundamental
run app.package.attacksurface com.someapp.dev
```

### Activities

List exported activities and intent filters:

```fundamental
run app.activity.info -i -a com.someapp.dev
```

Start an activity:

```fundamental
run app.activity.start --help

run app.activity.start --component com.someapp.dev com.someapp.dev.SomeActivity

run app.activity.start --component com.someapp.dev com.someapp.dev.SomeActivity --action android.intent.action.SOMEACTION --data-uri somescheme://somehost --extra string someKey someValue
```

Drozer is not able to pass arrays, lists, objects, etc. to intent filters due to console interface limitations.

### Providers

List exported and unexported content providers:

```fundamental
run app.provider.info -a com.someapp.dev

run app.provider.info -u -a com.someapp.dev
```

List, try to query, and do a vulnerability scan for all content providers' URIs:

```fundamental
run app.provider.finduri com.someapp.dev

run scanner.provider.finduris -a com.someapp.dev

run scanner.provider.injection -a com.someapp.dev

run scanner.provider.sqltables -a com.someapp.dev

run scanner.provider.traversal -a com.someapp.dev
```

## 9. Decompile an APK

**`d2j-dex2jar` \+ `jadx` gives the best results.**

Convert APK to JAR:

```fundamental
d2j-dex2jar base.apk -o base.jar
```

Decompile:

```fundamental
jadx -j $(grep -c processor /proc/cpuinfo) -d /root/Desktop/source/ /root/Desktop/base.jar
```

Make sure to specify a full path to the base.jar (preferred) or [base.apk](#pull-an-apk-baseapk); otherwise, JADX might not recognize it.

Make sure to specify a full path to the output directory; otherwise, it will default to `/usr/share/jadx/bin/` directory (i.e. to the root directory).

To inspect the source code using GUI, run the following command and open either base.jar (preferred) or base.apk:

```fundamental
jadx-gui
```

## 10. Repackage an APK

To do.

## 11. Tips and Security Best Practices

Bypass any keyboard restriction by copying and pasting data into an input field.

Access tokens should be short lived and invalidated once the user logs out.

Don't forget to test widgets, push notifications, app extensions, and Firebase.

## 12. Useful Websites and Tools

* [zxing.org/w/decode.jspx](https://zxing.org/w/decode.jspx) (decode QR codes)
* [odinforum.com](https://odinforum.com/discussion/11/latest-versions-of-odin-flashing-tool) (firmware flashing tool for Samsung devices)
* [samfrew.com](https://samfrew.com/) (firmwares for Samsung devices)
