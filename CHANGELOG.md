# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

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

[unreleased]: https://github.com/teal-bauer/GhydraMCP/compare/v1.4.0...HEAD
[1.4.0]: https://github.com/teal-bauer/GhydraMCP/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/teal-bauer/GhydraMCP/compare/v1.2...v1.3.0
[1.2]: https://github.com/teal-bauer/GhydraMCP/compare/v1.1...v1.2
[1.1]: https://github.com/teal-bauer/GhydraMCP/compare/1.0...v1.1
[1.0]: https://github.com/teal-bauer/GhydraMCP/releases/tag/1.0
