#This script was for a Ghidra Golf chalenge where hardcoded admin credentials needed to be identified.
#@author withzombies
#@category GhidraGolf
#@keybinding 
#@menupath 
#@toolbar 

def readString(address, max=64):
    a =  getBytes(toAddr(address), max)
    b = a[:a.index(0)]
    return ''.join([chr(x) for x in b])

ua = findBytes(None, "admin").getOffset()
u = readString(ua)
p = readString(ua + len('admin') + 3)

println(u + " " + p)
