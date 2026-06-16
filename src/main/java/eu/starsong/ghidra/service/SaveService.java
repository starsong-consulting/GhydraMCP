package eu.starsong.ghidra.service;

import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.List;

/**
 * Persist open programs to the project (Ghidra's "Save").
 *
 * <p>Runs on the calling (HTTP handler) thread, not the EDT: a save is disk I/O that Ghidra's
 * {@link DomainFile#save} is designed to do off the event thread, and holding the EDT for a
 * large save would freeze the UI.
 */
public class SaveService {

    /** Outcome of saving one program. */
    public record SaveResult(String program, boolean saved, String detail) {
    }

    /** Save one program if it has unsaved changes; a no-op (saved=false) when it doesn't. */
    public SaveResult save(Program program) {
        if (program == null) {
            throw new IllegalArgumentException("No program is currently loaded");
        }
        String name = program.getName();
        if (!program.isChanged()) {
            return new SaveResult(name, false, "no unsaved changes");
        }
        DomainFile df = program.getDomainFile();
        if (df == null || df.isReadOnly()) {
            throw new RuntimeException("Program '" + name + "' is read-only or not backed by a project file");
        }
        try {
            df.save(TaskMonitor.DUMMY);
            return new SaveResult(name, true, "saved");
        } catch (Exception e) {
            throw new RuntimeException("Failed to save '" + name + "': " + e.getMessage(), e);
        }
    }

    /** Save every open program that has unsaved changes. */
    public List<SaveResult> saveAllChanged(PluginTool tool) {
        List<SaveResult> results = new ArrayList<>();
        if (tool == null) {
            return results;
        }
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) {
            return results;
        }
        for (Program p : pm.getAllOpenPrograms()) {
            if (p.isChanged()) {
                results.add(save(p));
            }
        }
        return results;
    }
}
