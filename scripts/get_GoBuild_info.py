# Script to extract the Build ID from a Golang binary using Ghidra
#@author bfu
#@category GhidraGolf
#@keybinding 
#@menupath 
#@toolbar 

import codecs

# Define the function to extract the Build ID
def extractBuildID(program):
    b = []
    for section in program.getMemory().getBlocks():
        if section.getName() == ".gopclntab":
           for i in range(0, section.getSize() / 3):
             b += [section.getByte(section.getStart().add(i))]
    return b

def removeNonAscii(n):
    if n < 32 or n > 126:
        return 0x20
    return n

# Define the main function
def main():
    # Extract the Build ID
    bid = extractBuildID(currentProgram)
    bid = map(lambda c: removeNonAscii(c), bid)
    # Print the Build ID
    bid = ''.join([chr(x) for x in bid])
    bid = bid.split("main.main.func1")[1] # get data after funcs are done
    bid = bid.split(".go")
    # horrific
    bid = bid[len(bid) - 2]
    println(bid)

# Run the script
main()
