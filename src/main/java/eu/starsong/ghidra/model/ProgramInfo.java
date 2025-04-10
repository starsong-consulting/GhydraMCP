package eu.starsong.ghidra.model;

/**
 * Model class representing Ghidra program information.
 * This provides a structured object for program data instead of using Map<String, Object>.
 */
public class ProgramInfo {
    private String programId;
    private String name;
    private String languageId;
    private String compilerSpecId;
    private String imageBase;
    private long memorySize;
    private boolean isOpen;
    private boolean analysisComplete;

    /**
     * Default constructor for serialization frameworks
     */
    public ProgramInfo() {
    }

    /**
     * Full constructor
     */
    public ProgramInfo(String programId, String name, String languageId, String compilerSpecId,
                      String imageBase, long memorySize, boolean isOpen, boolean analysisComplete) {
        this.programId = programId;
        this.name = name;
        this.languageId = languageId;
        this.compilerSpecId = compilerSpecId;
        this.imageBase = imageBase;
        this.memorySize = memorySize;
        this.isOpen = isOpen;
        this.analysisComplete = analysisComplete;
    }

    /**
     * @return The program's unique identifier (typically the file pathname)
     */
    public String getProgramId() {
        return programId;
    }

    /**
     * @param programId The program's unique identifier
     */
    public void setProgramId(String programId) {
        this.programId = programId;
    }

    /**
     * @return The program's name
     */
    public String getName() {
        return name;
    }

    /**
     * @param name The program's name
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * @return The program's language ID
     */
    public String getLanguageId() {
        return languageId;
    }

    /**
     * @param languageId The program's language ID
     */
    public void setLanguageId(String languageId) {
        this.languageId = languageId;
    }

    /**
     * @return The program's compiler specification ID
     */
    public String getCompilerSpecId() {
        return compilerSpecId;
    }

    /**
     * @param compilerSpecId The program's compiler specification ID
     */
    public void setCompilerSpecId(String compilerSpecId) {
        this.compilerSpecId = compilerSpecId;
    }

    /**
     * @return The program's image base address
     */
    public String getImageBase() {
        return imageBase;
    }

    /**
     * @param imageBase The program's image base address
     */
    public void setImageBase(String imageBase) {
        this.imageBase = imageBase;
    }

    /**
     * @return The program's memory size in bytes
     */
    public long getMemorySize() {
        return memorySize;
    }

    /**
     * @param memorySize The program's memory size in bytes
     */
    public void setMemorySize(long memorySize) {
        this.memorySize = memorySize;
    }

    /**
     * @return Whether the program is currently open
     */
    public boolean isOpen() {
        return isOpen;
    }

    /**
     * @param open Whether the program is currently open
     */
    public void setOpen(boolean open) {
        isOpen = open;
    }

    /**
     * @return Whether analysis has been completed on the program
     */
    public boolean isAnalysisComplete() {
        return analysisComplete;
    }

    /**
     * @param analysisComplete Whether analysis has been completed on the program
     */
    public void setAnalysisComplete(boolean analysisComplete) {
        this.analysisComplete = analysisComplete;
    }

    /**
     * Builder pattern for ProgramInfo
     */
    public static class Builder {
        private String programId;
        private String name;
        private String languageId;
        private String compilerSpecId;
        private String imageBase;
        private long memorySize;
        private boolean isOpen;
        private boolean analysisComplete;

        public Builder programId(String programId) {
            this.programId = programId;
            return this;
        }

        public Builder name(String name) {
            this.name = name;
            return this;
        }

        public Builder languageId(String languageId) {
            this.languageId = languageId;
            return this;
        }

        public Builder compilerSpecId(String compilerSpecId) {
            this.compilerSpecId = compilerSpecId;
            return this;
        }

        public Builder imageBase(String imageBase) {
            this.imageBase = imageBase;
            return this;
        }

        public Builder memorySize(long memorySize) {
            this.memorySize = memorySize;
            return this;
        }

        public Builder isOpen(boolean isOpen) {
            this.isOpen = isOpen;
            return this;
        }

        public Builder analysisComplete(boolean analysisComplete) {
            this.analysisComplete = analysisComplete;
            return this;
        }

        public ProgramInfo build() {
            return new ProgramInfo(
                programId, name, languageId, compilerSpecId,
                imageBase, memorySize, isOpen, analysisComplete
            );
        }
    }

    /**
     * Create a new builder for ProgramInfo
     * @return A new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }
}
