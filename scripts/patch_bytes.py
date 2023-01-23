# This script patches a "hello world" string with "Hello Ghidra" and prints the offset
#@author Grant Hernandez (Mastadon: @digital@infosec.exchange, Twitter: @Digital_Cold, GitHub: @grant-h)
#@category GhidraGolf
#@keybinding 
#@menupath 
#@toolbar 
import base64
from ghidra.program.util import DefinedDataIterator

mem = currentProgram.getMemory()

for xstr in DefinedDataIterator.definedStrings(currentProgram):
    strv = xstr.getValue()

    if not strv.startswith("hello world!"):
        continue

    ref = xstr.getAddress().add(6)
    mem.setBytes(ref, b"Ghidra")
    println("Hello Ghidra at: " + ref.toString())
    break
