import numpy as np


def recursionFib(i: int):
    if i > 1:
        return recursionFib(i - 1) + recursionFib(i - 2)
    else:
        return i


def loopFib(i: int):
    arr = [1, 1]
    while len(arr) < i: arr.append(arr[-1] + arr[-2])
    return np.array(arr)[:i]


#print(recursionFib(25))
#print(loopFib(25))
