# This Ghidra Script solved a challenge where the flag was encoded bas64 information
#@author w1nd3x
#@category GhidraGolf
#@keybinding 
#@menupath 
#@toolbar 

from base64 import b64decode, b64encode

def isBase64(s):
    try:
        return b64encode(b64decode(s)) == s
    except Exception:
        return False

def getSection(section):
    for block in getMemoryBlocks():
        if block.getName() == section:
            start = block.getStart()
            end = block.getEnd()
            return start,end
    print("Section {} not found".format(section))
    return None,None

start, end = getSection('.rodata')
if start is not None:
    data = getDataAfter(start)
    while data is not None and data.getAddress().offset < end:
        if isBase64(data.value) and data.value[-1] == '=':
            println("Decoded: " + b64decode(data.value))
        data = getDataAfter(data.getAddress())
