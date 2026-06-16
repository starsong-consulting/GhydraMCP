package eu.starsong.ghidra.service;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramLocation;
import ghidra.util.task.TaskMonitor;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Run Ghidra scripts via the API: list them, run an existing one by name, or run ad-hoc
 * GhidraScript source. The script runs on the calling (HTTP handler) thread, which is off the
 * EDT, matching how Ghidra runs scripts in the background; {@code GhidraScript.execute} manages
 * its own transactions, so DB-modifying scripts work.
 *
 * <p>This is arbitrary code execution; the resource gates it behind an opt-in flag.
 */
public class ScriptService {

    private static final Pattern CLASS_NAME =
        Pattern.compile("class\\s+(\\w+)\\s+extends\\s+GhidraScript");

    /** A script discoverable in the source directories. */
    public record ScriptInfo(String name, String path, String category) {
    }

    /** Outcome of a script run: captured output plus success/error. */
    public record RunResult(String script, String output, boolean success, String error) {
    }

    /** Scripts found in the enabled source directories that have a provider (Java/Python/...). */
    public List<ScriptInfo> list() {
        List<ScriptInfo> out = new ArrayList<>();
        for (ResourceFile dir : GhidraScriptUtil.getEnabledScriptSourceDirectories()) {
            ResourceFile[] files = dir.listFiles();
            if (files == null) {
                continue;
            }
            for (ResourceFile f : files) {
                if (!f.isDirectory() && GhidraScriptUtil.hasScriptProvider(f)) {
                    out.add(new ScriptInfo(f.getName(), f.getAbsolutePath(), dir.getName()));
                }
            }
        }
        return out;
    }

    /** Run an existing script by file name (e.g. "FixupNoReturnFunctionsScript.java"). */
    public RunResult runByName(PluginTool tool, Program program, String name, String[] args) {
        ResourceFile file = GhidraScriptUtil.findScriptByName(name);
        if (file == null) {
            throw new IllegalArgumentException("Script not found: " + name);
        }
        return run(tool, program, file, args);
    }

    /**
     * Write ad-hoc GhidraScript source into the user script directory, run it, then delete the
     * temp source. The source must declare {@code public class &lt;Name&gt; extends GhidraScript};
     * the file is named to match so the provider can compile it.
     */
    public RunResult runSource(PluginTool tool, Program program, String source, String[] args) {
        Matcher m = CLASS_NAME.matcher(source);
        if (!m.find()) {
            throw new IllegalArgumentException(
                "Source must declare 'public class <Name> extends GhidraScript' with a run() method");
        }
        String className = m.group(1);
        File dir = GhidraScriptUtil.getUserScriptDirectory().getFile(false);
        File scriptFile = new File(dir, className + ".java");
        try {
            Files.writeString(scriptFile.toPath(), source);
            return run(tool, program, new ResourceFile(scriptFile), args);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to run ad-hoc script: " + e.getMessage(), e);
        } finally {
            scriptFile.delete();
        }
    }

    private RunResult run(PluginTool tool, Program program, ResourceFile file, String[] args) {
        StringWriter sw = new StringWriter();
        PrintWriter writer = new PrintWriter(sw);
        try {
            GhidraScriptProvider provider = GhidraScriptUtil.getProvider(file);
            if (provider == null) {
                throw new IllegalArgumentException(
                    "No script provider for " + file.getName() + " (unsupported extension?)");
            }
            GhidraScript script = provider.getScriptInstance(file, writer);
            if (args != null && args.length > 0) {
                script.setScriptArgs(args);
            }
            ProgramLocation location =
                program != null ? new ProgramLocation(program, program.getMinAddress()) : null;
            GhidraState state = new GhidraState(
                tool, tool != null ? tool.getProject() : null, program, location, null, null);
            script.execute(state, TaskMonitor.DUMMY, writer);
            writer.flush();
            return new RunResult(file.getName(), sw.toString(), true, null);
        } catch (Exception e) {
            writer.flush();
            String msg = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
            return new RunResult(file.getName(), sw.toString(), false, msg);
        }
    }
}
