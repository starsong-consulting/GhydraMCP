package eu.starsong.ghidra;

import eu.starsong.ghidra.api.ApiConstants;
import eu.starsong.ghidra.resource.*;
import eu.starsong.ghidra.server.GhydraServer;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.main.ApplicationLevelPlugin;
import ghidra.framework.plugintool.Plugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.Msg;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * GhydraMCP Plugin - Exposes Ghidra functionality via REST API.
 *
 * This is the new Javalin-based implementation of the plugin.
 */
@PluginInfo(
    status = PluginStatus.RELEASED,
    packageName = ghidra.app.DeveloperPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Ghidra HATEOAS interface",
    description = "Ghidra HATEOAS interface for all CodeBrowser instances in parallel.",
    servicesRequired = { ProgramManager.class }
)
public class GhydraPlugin extends Plugin implements ApplicationLevelPlugin {

    static {
        // Prints to the Ghidra launcher console before logger init.
        System.err.println("[GhydraPlugin] static init: class loaded from " +
            GhydraPlugin.class.getProtectionDomain().getCodeSource().getLocation());
    }

    public static final Map<Integer, GhydraPlugin> activeInstances = new ConcurrentHashMap<>();
    private static final Object baseInstanceLock = new Object();

    private GhydraServer server;
    private eu.starsong.ghidra.service.DecompilerService decompilerService;
    private int port;
    private boolean isBaseInstance = false;

    public GhydraPlugin(PluginTool tool) {
        super(tool);

        // Probe-and-claim atomically so two concurrently-constructed plugins
        // can't both pick the same free port.
        synchronized (activeInstances) {
            this.port = GhydraServer.findAvailablePort(activeInstances);
            activeInstances.put(port, this);
        }

        synchronized (baseInstanceLock) {
            if (port == ApiConstants.DEFAULT_PORT || activeInstances.get(ApiConstants.DEFAULT_PORT) == null) {
                this.isBaseInstance = true;
                Msg.info(this, "Starting as base instance on port " + port);
            }
        }

        Msg.info(this, "GhydraMCP loaded on port " + port);
        System.out.println("[GhydraMCP] Plugin loaded on port " + port);

        startServer();
    }

    private void startServer() {
        try {
            server = new GhydraServer(tool, port, castActiveInstances(), isBaseInstance);

            // One shared decompiler service per plugin instance: one native decompiler
            // process + one program listener, disposed in dispose() below.
            var functionService = new eu.starsong.ghidra.service.FunctionService();
            decompilerService = new eu.starsong.ghidra.service.DecompilerService(functionService);

            server.register(
                new RootResource(isBaseInstance),
                new FunctionResource(functionService, decompilerService),
                new SymbolResource(),
                new DataResource(),
                new MemoryResource(),
                new SegmentResource(),
                new XrefResource(),
                new ProgramResource(),
                new InstanceResource(),
                new AnalysisResource(),
                new EmulationResource(),
                new StructResource(),
                new DataTypeResource(),
                new ScalarResource(new eu.starsong.ghidra.service.ScalarService()),
                new VariableResource(new eu.starsong.ghidra.service.VariableService(decompilerService)),
                new ClassResource(),
                new NamespaceResource(),
                new ProjectResource(),
                new UiResource(),
                new ScriptResource(),
                new DevResource(port)
            );

            server.start();

            System.out.println("[GhydraMCP] HTTP server started on port " + port);

        } catch (Exception e) {
            // Deregister so clients don't discover a registered-but-dead instance,
            // and so the port frees up for a later retry.
            activeInstances.remove(port);
            server = null;
            Msg.error(this, "Failed to start HTTP server on port " + port + "; instance deregistered", e);
            System.err.println("[GhydraMCP] Failed to start HTTP server: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private Map<Integer, Object> castActiveInstances() {
        return (Map<Integer, Object>) (Map<?, ?>) activeInstances;
    }

    @Override
    public void dispose() {
        // Deregister first so /instances stops advertising a dying server.
        activeInstances.remove(port);
        if (server != null) {
            server.stop();
            System.out.println("[GhydraMCP] HTTP server stopped on port " + port);
        }
        if (decompilerService != null) {
            // Kills the native decompiler process and removes the program listener.
            decompilerService.dispose();
            decompilerService = null;
        }
        super.dispose();
    }

    public int getPort() {
        return port;
    }

    public boolean isBaseInstance() {
        return isBaseInstance;
    }

    /**
     * Build a metadata snapshot for this instance — what InstanceResource
     * surfaces under /instances so clients can pick the right port without
     * polling /info on every one.
     */
    public Map<String, Object> getInstanceSnapshot() {
        Map<String, Object> snapshot = new java.util.LinkedHashMap<>();
        snapshot.put("port", port);
        snapshot.put("url", "http://localhost:" + port);
        snapshot.put("isBaseInstance", isBaseInstance);
        snapshot.put("toolName", tool != null ? tool.getName() : null);

        ghidra.framework.model.Project project = tool != null ? tool.getProject() : null;
        snapshot.put("project", project != null ? project.getName() : null);

        ProgramManager pm = tool != null ? tool.getService(ProgramManager.class) : null;
        ghidra.program.model.listing.Program current = pm != null ? pm.getCurrentProgram() : null;
        if (current != null) {
            snapshot.put("file", current.getName());
            snapshot.put("executable", current.getExecutablePath());
            snapshot.put("architecture", current.getLanguageID().getIdAsString());
            snapshot.put("imageBase", current.getImageBase().toString());
        } else {
            snapshot.put("file", null);
        }
        return snapshot;
    }
}
