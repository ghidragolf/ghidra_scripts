# This script was used to print the decompilation of a given function and submit the hash of said decompilation as a flag.
#@author freethepockets
#@category GhidraGolf
#@keybinding 
#@menupath 
#@toolbar 

from ghidra.app.decompiler import DecompInterface
import ghidra.util.MD5Utilities
import md5

monitor = getMonitor()

ifc = DecompInterface()
ifc.openProgram(getCurrentProgram())
first_func = getFirstFunction()

results = ifc.decompileFunction(first_func, 0, monitor)
decomp = results.getDecompiledFunction().getC()

m = md5.new()
m.update(decomp)
m.digest()

println("Hash of first function code: " + m.hexdigest())
