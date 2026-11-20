// Writes the decompiled C of every function in the current program as a tree of text files.
// Argument: the tree's folder.
//@category Export
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class ExportTree extends GhidraScript {
    private static final int LISTED_SLOTS = 4;
    private static final Set<String> RTTI_LABELS = Set.of("vftable", "vftable_meta_ptr");
    // The decompiler's memory grows for as long as it works on a function it cannot finish: 150 MB each second on
    // the largest function of a 102 MB game executable. The slowest function that it did finish there took 29 seconds.
    private static final int DECOMPILE_TIMEOUT_SECONDS = 60;
    private static final int REPORT_INTERVAL = 1000;

    @Override
    public void run() throws Exception {
        Path tree = Path.of(getScriptArgs()[0]);
        Path state = tree.resolve("export.state");
        FunctionManager manager = currentProgram.getFunctionManager();
        long total = 0;
        for (Function ignored : manager.getFunctions(true)) {
            total++;
        }
        Files.writeString(state, "running 0 " + total + " 0\n");
        Map<Address, List<String>> vtables = writeVtables(tree.resolve("vtables.tsv"));

        long done = 0, failed = 0;
        DecompInterface decompiler = new DecompInterface();
        if (!decompiler.openProgram(currentProgram)) {
            throw new IOException("the decompiler did not start: " + decompiler.getLastMessage());
        }
        try (BufferedWriter index = Files.newBufferedWriter(tree.resolve("index.tsv"))) {
            index.write("address\tname\tstatus\n");
            for (Function function : manager.getFunctions(true)) {
                monitor.checkCancelled();
                Address entry = function.getEntryPoint();
                String address = entry.toString();
                String name = function.getName(true);
                DecompileResults results = decompiler.decompileFunction(function, DECOMPILE_TIMEOUT_SECONDS, monitor);
                boolean ok = results.decompileCompleted();
                if (!ok) {
                    failed++;
                }

                StringBuilder text = new StringBuilder("// function " + address + "  " + name + "\n");
                List<String> slots = vtables.getOrDefault(entry, List.of());
                if (slots.size() > LISTED_SLOTS) {
                    text.append("// referenced by ").append(slots.size()).append(" vtable slots, listed in vtables.tsv\n");
                }
                else {
                    for (String slot : slots) {
                        text.append("// vtable ").append(slot).append('\n');
                    }
                }
                text.append(ok ? results.getDecompiledFunction().getC()
                        : "// decompile failed: " + String.valueOf(results.getErrorMessage()).strip() + "\n");

                Path folder = tree.resolve("functions").resolve(address.substring(0, address.length() - 4));
                Files.createDirectories(folder);
                // Ghidra ends the lines of its C with CRLF on Windows; every file of the tree uses LF.
                Files.writeString(folder.resolve(address + ".c"), text.toString().replace("\r\n", "\n"));
                index.write(address + "\t" + name + "\t" + (ok ? "ok" : "failed") + "\n");
                if (++done % REPORT_INTERVAL == 0) {
                    Files.writeString(state, "running " + done + " " + total + " " + failed + "\n");
                }
            }
        }
        finally {
            decompiler.dispose();
        }
        // The worker publishes the tree only when it finds this line, so it must stay the last thing written.
        Files.writeString(state,
            "complete " + done + " " + total + " " + failed + " " + Application.getApplicationVersion() + "\n");
    }

    // Writes every (vtable, class, slot, function) row and returns each function's rows as "<vtable> <class> slot <n>".
    private Map<Address, List<String>> writeVtables(Path file) throws Exception {
        List<Symbol> tables = new ArrayList<>();
        currentProgram.getSymbolTable().getSymbolIterator("vftable", true).forEach(tables::add);
        tables.sort(Comparator.comparing(Symbol::getAddress));

        Map<Address, List<String>> byFunction = new HashMap<>();
        try (BufferedWriter out = Files.newBufferedWriter(file)) {
            out.write("vtable\tclass\tslot\tfunction\n");
            for (Symbol table : tables) {
                Address start = table.getAddress();
                String owner = table.getParentNamespace().getName(true);
                Address target;
                for (int slot = 0; (target = slotTarget(start, slot)) != null; slot++) {
                    out.write(start + "\t" + owner + "\t" + slot + "\t" + target + "\n");
                    byFunction.computeIfAbsent(target, key -> new ArrayList<>())
                            .add(start + " " + owner + " slot " + slot);
                }
            }
        }
        return byFunction;
    }

    // Returns where a slot points, or null past the vtable's end: the next vtable's RTTI pointer, or the first cell
    // that does not point into code. Ghidra's own array over a vtable is no guide: it stops at a slot that code
    // calls directly, and such a slot also gets a label that begins with "vftable".
    private Address slotTarget(Address table, int slot) {
        try {
            Address cell = table.addNoWrap(8L * slot);
            Symbol label = currentProgram.getSymbolTable().getPrimarySymbol(cell);
            if (slot > 0 && label != null && RTTI_LABELS.contains(label.getName())) {
                return null;
            }
            Address target = toAddr(currentProgram.getMemory().getLong(cell));
            MemoryBlock code = currentProgram.getMemory().getBlock(target);
            return code != null && code.isExecute() ? target : null;
        }
        catch (MemoryAccessException | AddressOverflowException e) {
            return null;
        }
    }
}
