# Contributing to GhydraMCP

Thank you for your interest in contributing to GhydraMCP! This document provides guidelines and information for contributors.

## Table of Contents

- [Project Structure](#project-structure)
- [Development Setup](#development-setup)
- [Versioning](#versioning)
- [Code Standards](#code-standards)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)

## Project Structure

GhydraMCP consists of two main components:

1. **Java Plugin for Ghidra** (`src/main/java/eu/starsong/ghidra/`):
   - Main class: `GhydraMCPPlugin.java`
   - API constants: `api/ApiConstants.java`
   - Endpoints: `endpoints/` directory
   - Data models: `model/` directory
   - Utilities: `util/` directory

2. **Python MCP Bridge** (`bridge_mcp_hydra.py`):
   - Implements the Model Context Protocol (MCP)
   - Connects AI assistants to the Ghidra plugin via HTTP

## Development Setup

### Prerequisites

- Java 21 (required for plugin development)
- Maven 3.8+
- Python 3.11+
- Ghidra (latest stable version recommended)

### Building from Source

```bash
# Clone the repository
git clone https://github.com/starsong-consulting/GhydraMCP.git
cd GhydraMCP

# Build the project
mvn clean package
```

This creates:
- `target/GhydraMCP-[version].zip` - The Ghidra plugin only
- `target/GhydraMCP-Complete-[version].zip` - Complete package with plugin and bridge script

### Installing for Development

1. Build the project as described above
2. In Ghidra, go to `File` -> `Install Extensions`
3. Click the `+` button
4. Select the `GhydraMCP-[version].zip` file
5. Restart Ghidra
6. Enable the plugin in `File` -> `Configure` -> `Developer`

### Python Bridge Setup

Install the required Python dependencies:

```bash
pip install mcp==1.6.0 requests==2.32.3
```

Or use uv:

```bash
uv pip install mcp==1.6.0 requests==2.32.3
```

## Versioning

GhydraMCP follows semantic versioning (SemVer) and uses explicit API versions:

### Version Numbers

When making changes, update version numbers in these locations:

1. **Plugin Version** in `src/main/java/eu/starsong/ghidra/api/ApiConstants.java`:
   ```java
   public static final String PLUGIN_VERSION = "v2.0.0";
   ```

2. **Bridge Version** in `bridge_mcp_hydra.py`:
   ```python
   BRIDGE_VERSION = "v2.0.0"
   ```

### API Versions

The API version is tracked separately from the implementation version:

1. **API Version** in `src/main/java/eu/starsong/ghidra/api/ApiConstants.java`:
   ```java
   public static final int API_VERSION = 2;
   ```

2. **Required API Version** in `bridge_mcp_hydra.py`:
   ```python
   REQUIRED_API_VERSION = 2
   ```

### When to Update Versions

- **Patch Version** (`x.y.Z`): Bug fixes and minor changes that don't affect API compatibility
- **Minor Version** (`x.Y.z`): New features that are backward compatible
- **Major Version** (`X.y.z`): Breaking changes that aren't backward compatible
- **API Version**: Only increment when making incompatible API changes

### Important Versioning Rules

1. **Bridge Modifications**: When modifying the MCP bridge script (`bridge_mcp_hydra.py`), update the `BRIDGE_VERSION` string but only update the `REQUIRED_API_VERSION` if the changes require API compatibility changes.

2. **Java Plugin Modifications**: When making changes to the Java plugin:
   - Update `PLUGIN_VERSION` string for all changes
   - Only increment `API_VERSION` when introducing breaking changes to the API

3. **API Compatibility**: The bridge script and Java plugin must have matching API versions to work together. The bridge verifies this at runtime.

## Code Standards

### Java Code Standards

- Follow Java naming conventions
- Add comprehensive JavaDoc comments for public methods
- Ensure proper exception handling
- Follow Ghidra extension development best practices
- Follow HATEOAS principles for API endpoints
- Implement proper null checks and input validation

### Python Code Standards

- Follow PEP 8 style guidelines
- Add docstrings for all functions
- Use type hints for function parameters and return types
- Implement proper error handling
- Ensure thread-safety for multi-threaded operations

### Commit Message Standards

Follow the conventional commits format:

```
<type>: <description>

[optional body]

[optional footer(s)]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring without functionality changes
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `build`: Build system changes
- `ci`: CI configuration changes
- `chore`: Other changes that don't modify src or test files

Example:
```
feat: Add support for string listing in binary files

This adds a new endpoint to list all defined strings in the binary
with pagination and filtering by content.

Closes #123
```

## Pull Request Process

1. **Branch Naming Convention**:
   - Features: `feature/short-description`
   - Fixes: `fix/issue-description`
   - Documentation: `docs/description`

2. **Before Creating a PR**:
   - Ensure all tests pass
   - Update documentation if needed
   - Update version numbers if needed
   - Add appropriate entries to CHANGELOG.md

3. **PR Template**:
   - Clearly describe the changes
   - Reference any related issues
   - Include any special testing instructions
   - List any breaking changes

4. **Review Process**:
   - At least one core contributor must review and approve
   - Address all requested changes
   - Ensure CI checks pass

## Release Process

1. **Preparation**:
   - Ensure all tests pass
   - Update version numbers in:
     - `src/main/java/eu/starsong/ghidra/api/ApiConstants.java`
     - `bridge_mcp_hydra.py`
   - Update CHANGELOG.md with release notes
   - Move content from "Unreleased" section to a new release section
   - Merge all changes to the main branch

2. **Creating a Release**:
   - Tag the release commit with the version number (e.g., `v2.0.0`)
   - Push the tag to GitHub
   - The GitHub Actions workflow will automatically:
     - Build the release artifacts
     - Create a GitHub release
     - Upload the artifacts

3. **Post-Release**:
   - Update version numbers to next development version
   - Create a new "Unreleased" section in CHANGELOG.md
   - Announce the release in appropriate channels

## Testing

Please include appropriate tests for your changes:

1. **HTTP API Tests**: For Java plugin endpoint changes
2. **MCP Bridge Tests**: For Python bridge functionality

Run the tests with:
```bash
python run_tests.py
```

See TESTING.md for more detailed information on testing procedures.

## Questions and Support

If you have questions or need help, please:
1. Open an issue on GitHub
2. Check existing documentation
3. Reach out to the maintainers directly

Thank you for contributing to GhydraMCP!