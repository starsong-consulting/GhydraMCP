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
    shortDescription = "GhydraMCP Plugin for AI Analysis",
    description = "Exposes program data via HATEOAS HTTP API for AI-assisted reverse engineering with MCP (Model Context Protocol).",
    servicesRequired = { ProgramManager.class }
)
public class GhydraMCP extends Plugin implements ApplicationLevelPlugin {

    public static final Map<Integer, GhydraMCP> activeInstances = new ConcurrentHashMap<>();
    private static final Object baseInstanceLock = new Object();

    private GhydraServer server;
    private int port;
    private boolean isBaseInstance = false;

    public GhydraMCP(PluginTool tool) {
        super(tool);

        this.port = GhydraServer.findAvailablePort(activeInstances);
        activeInstances.put(port, this);

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

            server.register(
                new RootResource(isBaseInstance),
                new FunctionResource(),
                new SymbolResource(),
                new DataResource(),
                new MemoryResource(),
                new SegmentResource(),
                new XrefResource(),
                new ProgramResource(),
                new InstanceResource(),
                new AnalysisResource()
            );

            server.start();

            System.out.println("[GhydraMCP] HTTP server started on port " + port);

        } catch (Exception e) {
            Msg.error(this, "Failed to start HTTP server on port " + port, e);
            System.err.println("[GhydraMCP] Failed to start HTTP server: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private Map<Integer, Object> castActiveInstances() {
        return (Map<Integer, Object>) (Map<?, ?>) activeInstances;
    }

    @Override
    public void dispose() {
        if (server != null) {
            server.stop();
            System.out.println("[GhydraMCP] HTTP server stopped on port " + port);
        }
        activeInstances.remove(port);
        super.dispose();
    }

    public int getPort() {
        return port;
    }

    public boolean isBaseInstance() {
        return isBaseInstance;
    }
}
