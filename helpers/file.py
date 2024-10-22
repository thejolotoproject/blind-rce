import string
import ast
import re

def get_headers(arr_data):
    arr = arr_data
    #remove first line, POST /login HTTP/2
    get_only_data_with_colon = [k for k in arr if ':' in k]
    header = list()
    for x in get_only_data_with_colon:
        if(x[:2] != "  "):   # removing data with spaces in front because
            header.append(x) # the scripts assume that this is a object or array
    return header


# it returns a string object or array from a file
# ex: {username:john_doe,password:123456} OR
# [
#    {data:{first_name:"john",last_name:"doe"}},
#    {data:{first_name:"bar",last_name:"foo"}}
# ]
def get_header_json_object(arr_data):
    arr = arr_data
    obj_str = ""
    for open_object_index, a in enumerate(arr):
        if("{" == a) | ("[" == a):
            close_object_index = len(arr)
            c = list()
            for b in range(open_object_index,close_object_index):
                c.append(arr[b])
            e = "".join(str(d) for d in c)
            obj_str = e.translate({ord(c): None for c in string.whitespace})
    return obj_str

# it returns a method, target and http from a file, POST, target, HTTP/2
def get_headers_target_method_http(arr_data):
    arr = arr_data
    
    # remove empty array
    while("" in arr):
        arr.remove("")
    
    #POST /login HTTP/2
    a = arr[0].split()
    target = ""
    for _, b in enumerate(arr):
        if ("HOST:" in b ) | ("Host:" in b) | ("host:" in b) :
            target = b

    # remove host: whether of its case sensitive, from Host: target.com to target.com
    target = re.sub("host:", "", target, flags=re.I) 
    path = a[1] # /login_path
    primary = {
        "target":http_normalize_slashes("%s%s"%(target,path)), # https://www.google.com
        "method": a[0], # POST
        "http": a[2] # HTTP/2
    }
    return primary

# removing extra slashes in the url and adding https as prefix
def http_normalize_slashes(url):
    url = str(url)
    segments = url.split('/')
    correct_segments = []
    for segment in segments:
        if segment != '':
            correct_segments.append(segment)
    first_segment = str(correct_segments[0])
    if first_segment.find('http') == -1:
        correct_segments = ['http:'] + correct_segments
    correct_segments[0] = correct_segments[0] + '/'
    normalized_url = '/'.join(correct_segments)
    return normalized_url.replace(" ", "")

# convert array header to object, to accept the 
# header in request it must be an object
# convert ['Host: www.google.com'] => {'Host': 'www.google.com'}
def header_array_to_object(arr = list()):
    obj_headers = {}
    # it is array when the 'arr' is from the argumetns
    if isinstance(arr, str):
        # convert the literal array in to actual array
        arr = ast.literal_eval(arr)
    # it is literal array when it comes from the file (-f --file)
    elif type(arr) is list:
        arr = list(arr)

    if(arr is not None):
        for a in arr:
            b = a.split(":")
            obj_headers[b[0]] = b[1].strip()
        return obj_headers
    return obj_headers