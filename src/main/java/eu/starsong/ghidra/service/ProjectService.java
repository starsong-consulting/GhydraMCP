package eu.starsong.ghidra.service;

import eu.starsong.ghidra.dto.ProjectDto;
import eu.starsong.ghidra.dto.ProjectFileDto;
import eu.starsong.ghidra.server.GhydraServer.NotFoundException;
import ghidra.app.services.ProgramManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.List;

public class ProjectService {

    /**
     * List all projects visible from this plugin context. In practice, Ghidra
     * plugins see exactly one active project, so this returns a list of
     * length 0 or 1.
     */
    public List<ProjectDto> listAll(PluginTool tool) {
        Project project = tool != null ? tool.getProject() : null;
        if (project == null) return new ArrayList<>();
        List<ProjectDto> out = new ArrayList<>();
        out.add(toDto(project));
        return out;
    }

    public ProjectDto getByName(PluginTool tool, String name) {
        for (ProjectDto p : listAll(tool)) {
            if (name.equals(p.name())) return p;
        }
        throw new NotFoundException("Project not found: " + name, "PROJECT_NOT_FOUND");
    }

    public ProjectDto getCurrent(PluginTool tool) {
        Project project = requireProject(tool);
        return toDto(project);
    }

    private ProjectDto toDto(Project project) {
        ProjectLocator locator = project.getProjectLocator();
        ProjectData data = project.getProjectData();

        String location = locator != null ? locator.getLocation() : null;
        String path = locator != null ? locator.getProjectDir().getAbsolutePath() : null;
        String rootPath = null;
        int fileCount = 0;
        int folderCount = 0;

        if (data != null) {
            DomainFolder root = data.getRootFolder();
            rootPath = root.getPathname();
            int[] counts = countFilesAndFolders(root);
            fileCount = counts[0];
            folderCount = counts[1];
        }
        return new ProjectDto(project.getName(), location, path, rootPath, fileCount, folderCount);
    }

    public List<ProjectFileDto> listFiles(PluginTool tool, String folderPath, boolean recursive) {
        Project project = requireProject(tool);
        ProjectData data = project.getProjectData();
        DomainFolder folder = data.getFolder(folderPath);
        if (folder == null) {
            throw new NotFoundException("Folder not found: " + folderPath, "FOLDER_NOT_FOUND");
        }
        List<ProjectFileDto> items = new ArrayList<>();
        if (recursive) {
            collectFiles(folder, items, tool);
        } else {
            for (DomainFolder sub : folder.getFolders()) {
                items.add(ProjectFileDto.folder(sub.getName(), sub.getPathname()));
            }
            for (DomainFile f : folder.getFiles()) {
                items.add(toFileDto(f, tool));
            }
        }
        return items;
    }

    public OpenResult openFile(PluginTool tool, String filePath) {
        Project project = requireProject(tool);
        ProjectData data = project.getProjectData();
        DomainFile file = data.getFile(filePath);
        if (file == null) {
            throw new NotFoundException("File not found: " + filePath, "FILE_NOT_FOUND");
        }
        ProgramManager pm = tool.getService(ProgramManager.class);
        if (pm == null) {
            throw new IllegalStateException("ProgramManager service not available");
        }
        Program program = pm.openProgram(file, DomainFile.DEFAULT_VERSION, ProgramManager.OPEN_CURRENT);
        if (program == null) {
            throw new IllegalStateException("Failed to open file: " + filePath);
        }
        return new OpenResult(filePath, file.getName(), true);
    }

    public record OpenResult(String path, String name, boolean opened) {}

    private Project requireProject(PluginTool tool) {
        Project project = tool != null ? tool.getProject() : null;
        if (project == null) {
            throw new NoProjectException("No project is currently open");
        }
        return project;
    }

    public static class NoProjectException extends RuntimeException {
        public NoProjectException(String message) { super(message); }
    }

    private void collectFiles(DomainFolder folder, List<ProjectFileDto> acc, PluginTool tool) {
        for (DomainFile f : folder.getFiles()) {
            acc.add(toFileDto(f, tool));
        }
        for (DomainFolder sub : folder.getFolders()) {
            collectFiles(sub, acc, tool);
        }
    }

    private ProjectFileDto toFileDto(DomainFile file, PluginTool tool) {
        String contentType = file.getContentType();
        boolean isProgram = contentType != null
            && (contentType.equals("Program")
                || contentType.equals(Program.class.getName())
                || contentType.endsWith(".Program"));

        Boolean isOpen = null;
        if (isProgram) {
            ProgramManager pm = tool.getService(ProgramManager.class);
            if (pm != null) {
                for (Program p : pm.getAllOpenPrograms()) {
                    if (p.getDomainFile().equals(file)) {
                        isOpen = true;
                        break;
                    }
                }
            }
            if (isOpen == null) isOpen = false;
        }
        return new ProjectFileDto(
            file.getName(), file.getPathname(), "file",
            contentType, isProgram, isOpen,
            file.getFileID(), file.getVersion(), file.getLastModifiedTime());
    }

    private int[] countFilesAndFolders(DomainFolder folder) {
        int fileCount = folder.getFiles().length;
        int folderCount = folder.getFolders().length;
        for (DomainFolder sub : folder.getFolders()) {
            int[] c = countFilesAndFolders(sub);
            fileCount += c[0];
            folderCount += c[1];
        }
        return new int[]{fileCount, folderCount};
    }
}
