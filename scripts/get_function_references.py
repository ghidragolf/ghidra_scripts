# This script grabs the references functions from a given function name
#@author birch
#@category GhidraGolf
#@keybinding 
#@menupath 
#@toolbar 

import ghidra.app.script.GhidraScript

functionName = "main" # Change to desired function name

fm = currentProgram.getFunctionManager()
futions = fm.getFunctions(True)

for fu in futions:
    if fu.getName() == functionName:
        entryPoint = fu.getEntryPoint()    # get the entry point of the function func

        refs = getReferencesTo(entryPoint)   # get the references to entryPoint

        break

for ref in refs:
    #if ref.getReferenceType().toString() == "UNCONDITIONAL_CALL":
    println("Reference to address offset: 0x" + str(ref.getFromAddress().getOffset()))
