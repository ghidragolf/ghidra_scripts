# Script to extract the build info from a Golang binary using Ghidra
#@author bfu
#@category GhidraGolf
#@keybinding 
#@menupath 
#@toolbar 

# get bytes in section
def getSectionBytes(program, section_name):
   b = []
   for section in program.getMemory().getBlocks():
      if section.getName() == section_name:
          for i in range(0, section.getSize()):
              b += [section.getByte(section.getStart().add(i))]
   return b

def removeNonAscii(n):
    # if not nice printable character, return space
    if n < 32 or n > 126:
        return 0x20
    return n

# Define the main function
def main():
   # replace non ascii characters with spaces
   section_bytes = map(lambda b: removeNonAscii(b), getSectionBytes(currentProgram, ".go.buildinfo"))
   section_bytes = "".join([chr(x) for x in section_bytes]) 
   println(section_bytes)

# Run the script
main()
