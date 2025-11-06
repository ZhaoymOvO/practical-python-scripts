import sys
sys.set_int_max_str_digits(25535)

def loopFib(i: int):
    if i<0: return []
    elif i==1: return [1]
    arr = [1, 1]
    while len(arr) < i:
        arr.append(arr[-1] + arr[-2])
    return arr
  
print(loopFib(32768))
