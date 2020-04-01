"""
    Dwarf - Copyright (C) 2020 Giovanni - iGio90 - Rocca
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with this program.
    If not, see <https://www.gnu.org/licenses/>
"""
from apk_parse.apk import APK
import atexit
import argparse
import frida
import gplaycli
import json
import os
import sys
import time


report = {}
apk_file = None
cli = None


def parse_message(message, data):
    if "payload" not in message:
        print(message)
        return
    if data:
        print("data? " + data)

    if "trace_report" not in report:
        report["trace_report"] = {}

    fnc = message["payload"]["function"]
    if fnc not in report["trace_report"]:
        report["trace_report"][fnc] = []
    report["trace_report"][fnc].append(message["payload"]["struct"])


def exit_handler():
    if not os.path.exists("reports"):
        os.mkdir("reports")

    if report:
        report["staus"] = 0
        report["updated"] = int(round(time.time() * 1000))
        if "app_info" in report:
            report_name = package_name + "_" + report["app_info"]["version_code"] + ".json"
        else:
            report_name = package_name + ".json"
        with open("reports/" + report_name, 'w') \
                as outfile:
            json.dump(report, outfile, indent=2)

    if "package_name" in report:
        run_cmd("adb shell am force-stop " + package_name)

    if apk_file and os.path.isfile(apk_file):
        os.remove(apk_file)


def run_cmd(cmd):
    os.system(cmd)


atexit.register(exit_handler)

parser = argparse.ArgumentParser(description='Tracer for Android built on top of Frida.')
parser.add_argument('-p', '--package', help="Package name to start and trace.", required=True)
parser.add_argument('-pd', '--package-download', help="Download and install package from Google Play Store.",
                    action="store_true", default=False)
parser.add_argument('-f', '--file-path', help="Specify apk file name for additional information.")
parser.add_argument('-s', '--script-path', help="Inject a custom payload instead of the default tracer")
args = parser.parse_args()

package_name = args.package
store_download = args.package_download
file_path = args.file_path
script_path = args.script_path

if store_download:
    print('Google Play: Logging in...')
    cli = gplaycli.GPlaycli()
    success, error = cli.connect()
    if not success:
        print("Cannot login to GooglePlay ( %s )" % error)
        sys.exit()

    if not os.path.exists("apk_files"):
        os.mkdir("apk_files")

    print('Google Play: downloading', package_name, 'please wait...')
    cli.download_folder = "apk_files"
    pkg_arr = [package_name]
    cli.download(pkg_arr)

    apk_file = "apk_files/" + package_name + ".apk"

    if not os.path.isfile(apk_file):
        print("Failed to download " + package_name + " from store.")
        sys.exit()
elif file_path:
    apk_file = file_path

report["package"] = package_name

if apk_file is not None:
    # generate info
    print("[*] Collecting app info")
    apk_info = APK(apk_file)
    report["app_info"] = {
        "md5": apk_info.file_md5,
        "cert_md5": apk_info.cert_md5,
        "file_size": apk_info.file_size,
        "version_name": apk_info.get_androidversion_name(),
        "version_code": apk_info.get_androidversion_code(),
        "main_activity": apk_info.get_main_activity(),
        "activities": apk_info.get_activities(),
        "services": apk_info.get_services(),
        "receivers": apk_info.get_receivers(),
        "providers": apk_info.get_providers(),
        "permissions": apk_info.get_permissions(),
        "certificates": []
    }

    report["app_info"]["certificates"].append(apk_info.cert_text)

    if cli is not None:
        store_info = cli.get_package_info(package_name)
        details = store_info['details']['appDetails']
        report["details"] = store_info['details']['appDetails']
        for image in store_info["image"]:
            if image["imageType"] == 4:
                report["details"]["icon_url"] = image["imageUrl"]

# install the app
if apk_file:
    print("[*] Installing " + package_name)
    run_cmd("adb install -r " + apk_file)

print("[*] Giving permissions to " + package_name)
run_cmd("adb shell pm grant " + package_name + " android.permission.ACCESS_COARSE_LOCATION")
run_cmd("adb shell pm grant " + package_name + " android.permission.ACCESS_FINE_LOCATION")
run_cmd("adb shell monkey -p " + package_name + " -c android.intent.category.LAUNCHER 1")

print("[*] Starting " + package_name)

js_api = open('api.js', "r").read()
if script_path:
    js_api = str.replace(js_api, '::tp::', open(script_path, "r").read())
else:
    js_api = str.replace(js_api, '::tp::', open('tracer_defaults.js', "r").read())

d = frida.get_usb_device()
pid = d.spawn(package_name)
session = d.attach(pid)
script = session.create_script(js_api)
script.on('message', parse_message)
script.load()
d.resume(pid)

sys.stdin.read()