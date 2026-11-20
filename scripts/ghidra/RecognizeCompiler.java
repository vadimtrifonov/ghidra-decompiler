// Names Visual Studio as the compiler of a program that has Microsoft C++ type information, when Ghidra's loader
// recognized no compiler.
// Argument: the tree's folder.
//@category Analysis
import ghidra.app.cmd.data.rtti.RttiUtil;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.opinion.PeLoader.CompilerOpinion.CompilerEnum;
import java.nio.file.Files;
import java.nio.file.Path;

public class RecognizeCompiler extends GhidraScript {
    // Ghidra reads the compiler from the DOS stub, and it analyses classes and exception data only for Visual Studio
    // and Clang. Steam's signature replaces the stub and Steamless clears it; without this a tree of such a file has
    // no classes. The type information is what Ghidra's own class analysis looks for first.
    @Override
    public void run() throws Exception {
        if (CompilerEnum.Unknown.toString().equals(currentProgram.getCompiler())
                && RttiUtil.findTypeInfoVftableAddress(currentProgram, monitor) != null) {
            currentProgram.setCompiler(CompilerEnum.VisualStudio.toString());
            println("No compiler was recognized; the program has Microsoft type information and is analysed as "
                    + "built with Visual Studio");
        }
        Files.writeString(Path.of(getScriptArgs()[0], "compiler.txt"), currentProgram.getCompiler() + "\n");
    }
}
