# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [2.0.0] - 2025-11-11

### Added
- **MCP Integration Refactor:** Refactored the Python bridge for improved MCP integration. (337f89e)
  - Introduced MCP resources for loading context (e.g., instances, functions, disassembly).
  - Added namespaced tools (e.g., `instance.*`, `function.*`, `data.*`) for better organization and discoverability.
  - Implemented a "current working instance" concept to simplify commands by implicitly targeting the active Ghidra instance.
- **Analysis Prompts:** Added pre-defined prompts for common analysis tasks, including `reverse_engineer_binary` for comprehensive analysis. (337f89e, 3134581)
- **String Data Listing:** Added a new endpoint to list string data in the binary, with pagination and filtering by content. Python bridge support via `list_strings()` function. (f71f4aa)
- **Comprehensive Data Manipulation:** Added tools/endpoints for creating (`create_data`), deleting (`delete_data`), renaming (`rename_data`), changing type (`set_data_type`), and combined updates (`update_data`) for data items. Supports common types (byte, word, dword, string, etc.). (6c28553, 5797fb3, 28870e9)
- **Enhanced Cross-Reference (Xrefs) Analysis:** Implemented accurate xref tools (`get_references_to`, `get_references_from`) using Ghidra's ReferenceManager. Features include detailed info, bi-directional search, type filtering, and simplified bridge output. (96788f3)
- **Memory Operations:** Added tools/endpoints for reading (`read_memory`) and writing (`write_memory`) to program memory. (454c739)
- **Function Addressing Flexibility:** MCP bridge now supports addressing functions by name or address. (4f3042f)
- **API Version Check:** Bridge script now verifies compatibility with the Java plugin (expects API v2). (fedd2d0)
- **Enhanced Decompiler Controls:** Added options for raw vs. clean pseudocode output and multiple simplification styles. (454c739)

### Changed
- **Bridge Refactor & Namespacing:** Reorganized bridge tools into namespaces (e.g., `instance.list_instances`, `function.get_function_details`) as part of the MCP integration refactor. (337f89e)
- **Breaking: HATEOAS API v2 & Bridge Update:** Migrated fully to a HATEOAS-driven API (v2). The Python bridge (`bridge_mcp_hydra.py`) now *exclusively* uses this API, removing legacy support. Responses are simplified for AI agents, including text representations for structured data (e.g., disassembly). All endpoints require HATEOAS compliance (e.g., `_links`). (4bc2267, 4f3042f)
- **Optimized Variable Listing:** Improved performance of the `/variables` endpoint with efficient pagination and a `globalOnly` filter. (6c865c4)
- **Standardized Responses:** Unified all endpoints to use structured JSON and standardized HATEOAS links. (454c739, 4bc2267)
- **Improved Error Handling:** Enhanced error reporting and parameter validation across the API and bridge. (454c739, 4f3042f, 3df129f)
- **API Documentation:** Updated documentation to reflect the HATEOAS v2 API and new features. (28870e9, 3fd0cf4)

### Fixed
- **Real Instruction Disassembly:** The `/disassembly` endpoint now provides actual instruction disassembly instead of placeholders. (3df129f)
- **Ghidra 11+ Compatibility:** Resolved various API compatibility issues, particularly for cross-references (`XrefsEndpoints`). (5dc59ce, 2b1fe6c, 0eaa19a, 9443101)
- **Data Operations:** Fixed issues with HTTP request body consumption, parameter naming (`type` vs `dataType`), and name preservation during type changes. (28870e9)
- **Function Commenting:** Corrected `set_decompiler_comment` to apply comments at the function level. (2a1607c)
- **Call Graph Parameter Handling:** Updated the CallGraph endpoint to properly accept both function name and address parameters for flexibility. (fa8cc64)
- **Endpoint Functionality:** Addressed various issues including endpoint registration, handling of program-dependent endpoints, URL encoding, transaction management, and inconsistent response formats. (various commits, e.g., 4bc2267)

## [1.4.0] - 2025-04-08

### Added
- Structured JSON communication between Python bridge and Java plugin
- Consistent response format with metadata (timestamp, port, instance type)
- Comprehensive test suites for HTTP API and MCP bridge
- Test runner script for easy test execution
- Detailed testing documentation in TESTING.md
- Origin checking for API requests
- Mutating tests for API functionality

### Changed
- Improved error handling in API responses
- Enhanced JSON parsing in the Java plugin
- Updated documentation with JSON communication details
- Standardized API responses across all endpoints
- Improved version handling in build system

### Fixed
- Build complete package in `package` phase
- Versioning and naming of JAR files
- GitHub Actions workflow permissions
- Extension ZIP inclusion in complete package
- ProgramManager requirement
- Git tag fetching functionality
- MCP bridge test failures

## [1.3.0] - 2025-04-02

### Added
- Added docstrings for all @mcp.tool functions
- Variable manipulation tools (rename/retype variables)
- New endpoints for function variable management
- Dynamic version output in API responses
- Enhanced function analysis capabilities
- Support for searching variables by name
- New tools for working with function variables:
  - get_function_by_address
  - get_current_address
  - get_current_function
  - decompile_function_by_address
  - disassemble_function
  - set_decompiler_comment
  - set_disassembly_comment
  - rename_local_variable
  - rename_function_by_address
  - set_function_prototype
  - set_local_variable_type

### Changed
- Improved version handling in build system
- Reorganized imports in bridge_mcp_hydra.py
- Updated MANIFEST.MF with more detailed description

## [1.2] - 2025-03-30

### Added
- Enhanced function analysis capabilities
- Additional variable manipulation tools
- Support for multiple Ghidra instances

### Changed
- Improved error handling in API calls
- Optimized performance for large binaries

## [1.1] - 2025-03-30

### Added
- Initial release of GhydraMCP bridge
- Basic Ghidra instance management tools
- Function analysis tools 
- Variable manipulation tools

## [1.0] - 2025-03-24

### Added
- Initial project setup
- Basic MCP bridge functionality

[unreleased]: https://github.com/teal-bauer/GhydraMCP/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/teal-bauer/GhydraMCP/compare/v1.4.0...v2.0.0
[1.4.0]: https://github.com/teal-bauer/GhydraMCP/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/teal-bauer/GhydraMCP/compare/v1.2...v1.3.0
[1.2]: https://github.com/teal-bauer/GhydraMCP/compare/v1.1...v1.2
[1.1]: https://github.com/teal-bauer/GhydraMCP/compare/1.0...v1.1
[1.0]: https://github.com/teal-bauer/GhydraMCP/releases/tag/1.0