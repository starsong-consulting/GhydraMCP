# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

## [1.2.0] - 2024-06-15

### Added
- Enhanced function analysis capabilities
- Additional variable manipulation tools
- Support for multiple Ghidra instances

### Changed
- Improved error handling in API calls
- Optimized performance for large binaries

## [1.0.0] - 2024-03-15

### Added
- Initial release of GhydraMCP bridge
- Basic Ghidra instance management tools
- Function analysis tools 
- Variable manipulation tools
