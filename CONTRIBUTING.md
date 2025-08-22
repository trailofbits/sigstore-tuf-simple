# Contributing to sigstore-tuf-simple

Thank you for your interest in contributing to sigstore-tuf-simple! This document provides guidelines for contributing to this development tool.

## Overview

This project is a development and testing utility for Sigstore TUF repositories. It is not intended for production use and focuses on enabling developers to quickly set up test environments with various Sigstore service configurations.

## Getting Started

### Prerequisites

- Go 1.24.0 or later
- Git
- Basic understanding of Sigstore, TUF, and PKI concepts

### Setting Up Development Environment

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/trailofbits/sigstore-tuf-simple.git
   cd sigstore-tuf-simple
   ```

2. Build the project:
   ```bash
   go build
   ```

3. Run tests:
   ```bash
   go test -v
   ```

## Development Guidelines

### Code Style

- Follow standard Go conventions and formatting
- Use `gofmt` to format your code
- Run `go vet` to check for common Go mistakes
- Write clear, descriptive variable and function names
- Keep functions focused and reasonably sized

### Testing

- Write unit tests for new functionality
- Ensure all tests pass before submitting a PR
- Include edge cases and error conditions in tests
- Test both success and failure paths
- Mock external dependencies (HTTP calls, file system operations)

### Documentation

- Update README.md if adding new features or changing usage
- Document public functions and types with Go doc comments
- Include examples in documentation where helpful
- Update command-line help text for new options

## Submitting Changes

### Pull Request Process

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes, ensuring:
   - Code follows Go conventions
   - Tests pass
   - Documentation is updated
   - Commit messages are clear

3. Push your branch and create a pull request

4. Address any feedback from maintainers

### Commit Messages

Use clear, descriptive commit messages:

```
Add support for custom TSA certificate chains

- Allow TSA configurations to specify custom certificate chain files
- Update documentation with TSA certificate chain examples
- Add tests for TSA certificate parsing
```

## Questions?

Feel free to open an issue for questions about:
- How to implement a feature
- Clarification on requirements
- Discussion of potential improvements

## License

By contributing to this project, you agree that your contributions will be licensed under the Apache License 2.0.
