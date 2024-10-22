def arr_to_string_sanitizer (arr):
     r = "".join(str(x) for x in arr)
     r = r.replace("+"," ")
     return r   