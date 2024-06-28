# Contribution Guidelines

Thank you for considering contributing to RITA! We appreciate your interest and support. Please take a moment to review the following guidelines before making your contribution.

## Table of Contents
1. [Code of Conduct](#code-of-conduct)
2. [How to Contribute](#how-to-contribute)
    - [Reporting Bugs](#reporting-bugs)
    - [Suggesting Features](#suggesting-features)
    - [Answering Questions](#answering-questions)
    - [Contributing Code](#contributing-code)
3. [Development Process](#development-process)
    - [Prerequisites](#prerequisites)
    - [Setting Up Your Development Environment](#setting-up-your-development-environment)
    - [Style](#style)
    - [Testing](#testing)
    - [Submitting a Pull Request](#submitting-a-pull-request)
    - [PR Has Been Reviewed and Merged](#pr-has-been-reviewed-and-merged)
4. [Contact](#contact)

## Code of Conduct

We strive to maintain a welcoming and inclusive community for everyone who wants to contribute to this project. Therefore, we kindly ask you to adhere to the following code of conduct in all interactions related to this project:

* Treat all contributors with respect and consideration. Discrimination, harassment, or offensive behavior will not be tolerated.
* Communicate in a productive and professional manner.
* Be capable of both giving and accepting constructive feedback
* Work with others to resolve conflicts and reach a consensus.
* Value and acknowledge the contributions of others.
* Use welcoming and inclusive language
* Help create a positive and collaborative environment by treating everyone with kindness and empathy


## How to Contribute

### Reporting Bugs

If you find a bug, please first verify that the issue has not already been reported [here](https://github.com/activecm/rita/issues). If it has not been reported yet, open a new issue. Include as much detail as possible to help us understand and reproduce the bug. Follow these guidelines:

1. Use a clear and descriptive title.
2. Provide a step-by-step description of the bug and how to reproduce it.
3. Include any relevant screenshots, logs, or error messages.
4. Mention the version of the project you are using and the environment (e.g., OS, CPU, RAM, hard drive space, etc.)

### Suggesting Features

To suggest a new feature, please create an issue with the following information:

1. Use a clear and descriptive title.
2. Provide a detailed description of the feature and its benefits.
3. Explain any potential use cases or examples of how the feature could be used.
4. If possible, provide examples or mockups of the feature.

### Answering Questions

Rather than creating an issue to request help with the project, we encourage users to join our [Threat Hunter Discord](https://discord.gg/threathunter) to ask questions and seek guidance. The **#rita** and **#rita-development** channels are focused on this project. If you have experience with the project, please consider helping others by answering their questions on Discord. This will help us keep the issue tracker focused on bugs and feature requests and provide a way for our community to communicate and support each other.

### Contributing Code

The steps below outline the process for contributing code to this project. Before you begin, please ensure that you have read and understood our [Code of Conduct](#code-of-conduct). Please also review the [Development Process](#development-process) section for more detailed guidelines on this process.

1. Set up your development environment as described in the [Prerequisites](#prerequisites) section.
3. Verify that your intended contribution is associated with an issue. If not, create one using the guidelines above.
2. Create a new branch for your contribution (e.g., `feature/awesome-feature` or `bugfix/issue`).
3. Make your changes
4. Write tests to cover your changes.
5. Commit your changes with clear and descriptive commit messages.
6. Push your branch to your forked repository.
7. Create a pull request to the `main` branch of the original repository.
8. Your pull request will be reviewed by the maintainers, and you may be asked to make changes before it is accepted.

## Development Process

### Prerequisites
Contribution to this project will require the following:
 * [Go](https://golang.org/doc/install) (Check `go.mod` for the correct version to install)
 * [Docker](https://docs.docker.com/engine/installation/)

### Setting Up Your Development Environment
1. Fork the repository on GitHub.
2. Clone your fork to your local machine:
   ```
   git clone https://github.com/your-username/rita.git 
   ```
3. Navigate to the project directory:
   ```
   cd rita
   ```
3. Install the project dependencies:
   ```
   go mod download
   ```
4. Run the tests to verify that everything is working correctly:
   ```
   go test ./...
   ```
5. Start the backend containers for Clickhouse:
   ```
   docker-compose up -d
   ```
6. Run the project:
    * Using Go:
        ```
        go run main.go <command> <flags>
        ```
    * Using a Compiled Binary:
        ```
        make
        ./rita <command> <flags>
        ```
    * Using Docker:
        ```
        ./rita.sh
        ```
7. Make your changes and ensure that they pass the tests before submitting a pull request.

For more information about setting up a development environment, see the [docs](docs/Development.md).

### Style
Please follow these guidelines to ensure consistency across the project:

- Use clear and descriptive variable and function names.
- Write clear and concise comments where necessary.
- Format your code using a golang extension on your editor or the `gofmt` tool.
   ```
   gofmt -s -w .
   ```
- Use golangci-lint for linting with the configuration specified in .golangci.yml:
   ```
   golangci-lint run
   ```
- Write tests for new functionality and ensure existing tests pass.

### Testing
Writing tests is a crucial part of contributing to our project. Please ensure that your code changes include tests where applicable. Here are some guidelines for writing and running tests:

**Unit Tests**: 
Write unit tests for individual functions and methods. Place your test files in the same package as the code being tested and name the test files with a _test.go suffix.

**Integration Tests**:
Write integration tests for testing interactions between different components. Integration tests should also be written to test the final results of the import process against known, expected values. These tests should be placed in the integration package.


### Submitting a Pull Request
When submitting a pull request, please follow these steps:
- Verify that your PR is based on a single logical change.
- Check that your commit messages are clear and descriptive.
- Ensure that your code follows our [style guide](#style-guide)
- Write or update tests to cover your changes.
- Verify that all tests pass.
- Provide a clear and concise summary of all changes in the PR description.
- Reference all relevant issues in the PR description (e.g., "Closes #123").

Once you have submitted your PR, the maintainers will review it and provide feedback. You may be asked to make changes before your PR is accepted.

### PR Has Been Reviewed and Merged
🎉✨ Congratulations and thank you for contributing to RITA! ✨🎉


## Contact
If you have any questions please reach out to us on our [Threat Hunter Discord](https://discord.gg/threathunter) via the **#rita** or **#rita-development** channels.