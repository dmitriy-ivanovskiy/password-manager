# Contributing to Secure Password Manager

First of all, thank you for considering contributing to the Secure Password Manager! Your help is essential for making this project better and more secure.

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

- **Ensure the bug was not already reported** by searching on GitHub under [Issues](https://github.com/yourusername/password-manager/issues).
- If you're unable to find an open issue addressing the problem, [open a new one](https://github.com/yourusername/password-manager/issues/new). Be sure to include a **title and clear description**, as much relevant information as possible, and a **code sample** or an **executable test case** demonstrating the expected behavior that is not occurring.
- **For security vulnerabilities**, please refer to the [SECURITY.md](SECURITY.md) file for our security disclosure process instead of opening a public issue.

### Suggesting Enhancements

- **Check the issues list** for existing enhancement requests.
- **Determine the appropriate repository** for your enhancement suggestion.
- **Provide a clear and detailed explanation** of the feature you want to see.
- **Consider including examples** of how the enhancement would work.

### Pull Requests

1. **Fork the repository** and create your branch from `main`.
2. **Follow the coding style** of the project.
3. **Add tests** if applicable.
4. **Ensure the test suite passes**.
5. **Update the documentation** if needed.
6. **Make sure your code lints**.
7. **Issue that pull request**!

## Development Process

### Setting Up Development Environment

1. Clone the repository:
```bash
git clone https://github.com/yourusername/password-manager.git
cd password-manager
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install development dependencies:
```bash
pip install -r requirements.txt -r requirements-dev.txt
```

4. Run the tests to make sure everything is working:
```bash
pytest
```

### Code Style

This project follows the [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide for Python code. Please ensure your code adheres to these standards.

Some key points:
- Use 4 spaces for indentation
- Keep lines under 100 characters
- Use docstrings for all public methods, classes, and modules
- Use meaningful variable and function names

### Testing

- Write tests for all new features or bug fixes.
- Run the test suite before submitting a pull request:
```bash
pytest
```

- To check test coverage:
```bash
pytest --cov=app --cov-report=term-missing
```

### Documentation

- Update the documentation if you're changing any functionality.
- Write clear, concise docstrings for functions and classes.
- Keep the README updated with any significant changes.

## Security Considerations

Since this is a security-focused application:

1. **Never commit sensitive information** like passwords, API keys, etc.
2. **Pay extra attention to input validation** to prevent security issues.
3. **Review cryptographic implementations** carefully.
4. **Think about potential security impacts** for any changes.

## License

By contributing to this project, you agree that your contributions will be licensed under its MIT License. 