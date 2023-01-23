#Ghidra Script to list the methods of each global class contained within this program.
#@author w1nd3x
#@category GhidraGolf
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.program.model.symbol import SymbolType

symtab = currentProgram.getSymbolTable()
for cl in symtab.getClassNamespaces():
    for sym in symtab.getSymbols(cl):
        if sym.getSymbolType() == SymbolType.FUNCTION:
            println(cl.getName() + " : " + sym.getName())
