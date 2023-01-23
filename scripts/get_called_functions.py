# This script grabs the functions that call a given function
#@author w1nd3x
#@category GhidraGolf
#@keybinding 
#@menupath 
#@toolbar 

def run():
    functions = {}
    for function in getCurrentProgram().getFunctionManager().getFunctions(True):
        functions[function.getName()] = function
       
    for func in function['_secondMain'].getCalledFunctions(monitor):
        println("Called function: " + func.getName())
    
run()

