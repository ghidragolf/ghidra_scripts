// Script to hook functions and perform pcode emulation. Originally developed for "kill switch"  challenge for ShmooCon Ghidra Golf 2023
//@author mrexodia
//@category GhidraGolf
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.app.services.ConsoleService;
import ghidra.pcode.emulate.EmulateExecutionState;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.app.emulator.*;
import ghidra.util.exception.NotFoundException;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.security.*;

public class pcode_emulation extends GhidraScript {
    public void log(String format, Object... args) {
        println(String.format(format, args));
    }

    private Address getAddress(long offset) {
        return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    @FunctionalInterface
    public interface ThrowingLambda {
        void run() throws Exception;

        static Runnable unchecked(ThrowingLambda f) {
            return () -> {
                try {
                    f.run();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            };
        }
    }

    private static final long CONTROLLED_RETURN_OFFSET = 0;

    private EmulatorHelper emuHelper;

    private HashMap<Address, ThrowingLambda> breakpointHandlers = new HashMap<>();

    private void setBreakpoint(Address address, ThrowingLambda callback) {
        breakpointHandlers.put(address, callback);
        emuHelper.setBreakpoint(address);
    }

    int pointerSize = 4;

    private Address fakeImportAddress;
    private boolean singleStep = true;

    private void hookImport(String name, ThrowingLambda callback) throws NotFoundException {
        var fakeAddress = fakeImportAddress;
        var count = 0;
        var symbol = currentProgram.getSymbolTable().getExternalSymbol(name);
        for (var reference : symbol.getReferences()) {
            if (reference.getReferenceType() == RefType.DATA) {
                debug("symbol %s -> %s %s\n", reference.getFromAddress(), reference.getToAddress(), reference.getReferenceType());
                emuHelper.writeMemoryValue(reference.getFromAddress(), fakeAddress.getPointerSize(), fakeAddress.getOffset());
                count++;
            }
        }
        if (count == 0) {
            throw new NotFoundException("Could not find any point to import " + name);
        }

        fakeImportAddress = fakeImportAddress.add(0x10);
        setBreakpoint(fakeAddress, () -> {
            debug("Running import hook " + fakeAddress + ":" + name);
            callback.run();
            emulateReturn();
        });
    }

    private void debug(String format, Object... args) {
        if (debugMode)
            log(format, args);
    }

    private void emulateReturn() throws Exception {
        // force early return
        long returnOffset = emuHelper.readStackValue(0, pointerSize, false).longValue();
        debug("return to: 0x%X", returnOffset);
        emuHelper.writeRegister(emuHelper.getPCRegister(), returnOffset);
        var sp = emuHelper.readRegister(emuHelper.getStackPointerRegister()).longValue();
        emuHelper.writeRegister(emuHelper.getStackPointerRegister(), sp - pointerSize);
    }

    private Address getArgumentValue(int index) throws Exception {
        // TODO: support more architectures
        var offset = pointerSize * (index + 1);
        var value = emuHelper.readStackValue(offset, pointerSize, false).longValue();
        return getAddress(value);
    }

    private String getArgumentString(int index) throws Exception {
        var ptr = getArgumentValue(index);
        return emuHelper.readNullTerminatedString(ptr, 0x1000);
    }

    private void setFunctionResult(long value) throws Exception {
        // TODO: support more architectures
        emuHelper.writeRegister("EAX", value);
    }

    boolean keepRunning = false;

    private void stopEmulation() {
        debug("Stopping emulation");
        keepRunning = false;
    }

    public static String escape(String s) {
        return s.replace("\\", "\\\\")
                .replace("\t", "\\t")
                .replace("\b", "\\b")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\f", "\\f")
                .replace("\'", "\\'")
                .replace("\"", "\\\"");
    }

    boolean debugMode = false;

    public void run() throws Exception {

        if (debugMode)
            state.getTool().getService(ConsoleService.class).clearMessages();

        var RegGetValueA = currentProgram.getSymbolTable().getExternalSymbol("RegGetValueA");

        Function killswitchFunction = null;
        for (var reference : RegGetValueA.getReferences()) {
            if (reference.getReferenceType() != RefType.DATA) {
                var containingFunction = getFunctionContaining(reference.getFromAddress());
                if (killswitchFunction == null) {
                    killswitchFunction = containingFunction;
                } else if (killswitchFunction != containingFunction) {
                    log("Function not matching");
                    return;
                }
            }
        }
        if (killswitchFunction == null) {
            log("Killswitch not found");
            return;
        }

        var mainFunctionEntry = killswitchFunction.getEntryPoint();
        log("killswitch: %s", mainFunctionEntry);

        // Establish emulation helper
        emuHelper = new EmulatorHelper(currentProgram);
        pointerSize = currentProgram.getMaxAddress().getPointerSize();
        var stepCount = 0;
        try {
            // Initialize stack pointer (not used by this example)
            long stackOffset =
                    (mainFunctionEntry.getAddressSpace().getMaxAddress().getOffset() >>> 1) - 0x7fff;
            emuHelper.writeRegister(emuHelper.getStackPointerRegister(), stackOffset);

            // Allocate some space for fake imports
            fakeImportAddress = getAddress(stackOffset - 0x10000);

            hookImport("strlen", () -> {
                var ptr = getArgumentValue(0);
                var str = emuHelper.readNullTerminatedString(ptr, 0x1000);
                debug("strlen(%s \"%s\") = %d", ptr, str, str.length());
                setFunctionResult(str.length());
            });

            hookImport("RegGetValueA", () -> {
                var hKey = getArgumentValue(0);
                var lpSubKey = getArgumentString(1);
                var lpValue = getArgumentString(2);
                var dwFlags = getArgumentValue(3);
                var pdwType = getArgumentValue(4);
                var pvData = getArgumentValue(5);
                var pcbData = getArgumentValue(6);
                debug("RegGetValueA(\n\thKey: %s,\n\tlpSubKey:\"%s\",\n\tlpValue: \"%s\",\n\tdwFlags: %s,\n\tpdwType: %s,\n\tpvData: %s,\n\tpcbData: %s\n)",
                        hKey,
                        escape(lpSubKey),
                        escape(lpValue),
                        dwFlags,
                        pdwType,
                        pvData,
                        pcbData);
                // challenge output
                log(lpSubKey);
                log(lpValue);
                var result = "hello";
                emuHelper.writeMemory(pvData, result.getBytes());
                emuHelper.writeMemoryValue(pcbData, pointerSize, result.length());
                setFunctionResult(0);
            });

            hookImport("strcmp", () -> {
                var a = getArgumentString(0);
                var b = getArgumentString(1);
                var result = a.compareTo(b);
                debug("strcmp(\"%s\", \"%s\") -> %d", escape(a), escape(b), result);
                setFunctionResult(result);
            });

            // Set controlled return location so we can identify return from emulated function
            var controlledReturnAddr = getAddress(CONTROLLED_RETURN_OFFSET);
            emuHelper.writeStackValue(0, 8, CONTROLLED_RETURN_OFFSET);
            emuHelper.setBreakpoint(controlledReturnAddr);

            // This example directly manipulates the PC register to facilitate hooking
            // which must alter the PC during a breakpoint, and optional stepping which does not
            // permit an initial address to be specified.
            emuHelper.writeRegister(emuHelper.getPCRegister(), mainFunctionEntry.getOffset());
            debug("EMU starting at " + emuHelper.getExecutionAddress());

            keepRunning = true;

            // Execution loop until return from function or error occurs
            while (!monitor.isCancelled()) {
                // Use stepping if needed for troubleshooting - although it runs much slower
                var success = singleStep ? emuHelper.step(monitor) : emuHelper.run(monitor);
                stepCount++;
                if (stepCount >= 100000 || !keepRunning) {
                    break;
                }

                Address executionAddress = emuHelper.getExecutionAddress();
                if (monitor.isCancelled()) {
                    debug("Emulation cancelled");
                    return;
                }

                if (!success) {
                    String lastError = emuHelper.getLastError();
                    printerr("Emulation Error: " + lastError);
                    return;
                }

                debug("address: %s", executionAddress);

                if (executionAddress.equals(controlledReturnAddr)) {
                    debug("Returned from function");
                    return;
                }

                if (emuHelper.getEmulateExecutionState() != EmulateExecutionState.BREAKPOINT) {
                    // assume we are stepping and simply return
                    continue;
                }

                // Handle the breakpoint
                var handler = breakpointHandlers.get(executionAddress);
                if (handler == null) {
                    throw new NotFoundException("Unhandled breakpoint at " + executionAddress);
                }
                handler.run();

                if (!keepRunning)
                    break;
            }
        } finally {
            // cleanup resources and release hold on currentProgram
            emuHelper.dispose();
        }

        debug("step count: %d", stepCount);
    }
}
