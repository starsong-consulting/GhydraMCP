package eu.starsong.ghidra.server;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import io.javalin.json.JsonMapper;
import org.jetbrains.annotations.NotNull;

import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;

/**
 * GSON-based JSON mapper for Javalin.
 * Provides consistent JSON serialization/deserialization across the application.
 */
public class GsonMapper implements JsonMapper {

    private final Gson gson;

    public GsonMapper() {
        this.gson = new GsonBuilder()
            .setPrettyPrinting()
            .disableHtmlEscaping()
            .serializeNulls()
            .create();
    }

    public GsonMapper(Gson gson) {
        this.gson = gson;
    }

    @NotNull
    @Override
    public String toJsonString(@NotNull Object obj, @NotNull Type type) {
        return gson.toJson(obj, type);
    }

    @NotNull
    @Override
    public <T> T fromJsonString(@NotNull String json, @NotNull Type type) {
        return gson.fromJson(json, type);
    }

    @NotNull
    @Override
    public <T> T fromJsonStream(@NotNull InputStream stream, @NotNull Type type) {
        return gson.fromJson(new InputStreamReader(stream, StandardCharsets.UTF_8), type);
    }

    /**
     * Get the underlying GSON instance.
     */
    public Gson gson() {
        return gson;
    }
}
