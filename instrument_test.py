import atexit
import argparse
import frida
import os
import sys


def parse_message(message, data):
    print(message)


def exit_handler():
    run_cmd("adb shell am force-stop " + package_name)


def run_cmd(cmd):
    os.system(cmd)


atexit.register(exit_handler)

parser = argparse.ArgumentParser(description='Trace app for SpotifApp.')
parser.add_argument('-p', '--package', help="Package name to start and trace.", required=True)
args = parser.parse_args()

package_name = args.package

# start frida server
run_cmd("adb shell su -c setenforce 0")
run_cmd("adb shell su -c killall -9 frida")
run_cmd("adb shell su -c frida &")

print("[*] Killing " + package_name)
run_cmd("adb shell am force-stop " + package_name)
print("[*] Starting " + package_name)
run_cmd("adb shell pm grant " + package_name + " android.permission.ACCESS_COARSE_LOCATION")
run_cmd("adb shell pm grant " + package_name + " android.permission.ACCESS_FINE_LOCATION")
run_cmd("adb shell monkey -p " + package_name + " -c android.intent.category.LAUNCHER 1")

process = frida.get_usb_device().attach(package_name)
print("Frida attached.")
script = process.create_script(open("instrument_test.js", "r").read())
print("Dumper loaded.")
script.on('message', parse_message)
print("parse_message registered within script object.")
script.load()
sys.stdin.read()
