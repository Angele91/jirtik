# Jirtik

Jirtik is a command-line tool that helps you create TickTick tasks from JIRA issues, streamlining your task management workflow.

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/jirtik.git
cd jirtik
```

2. Install the package:
```bash
make publish
```

## Configuration

Before using Jirtik, you need to configure your credentials for both JIRA and TickTick:

```bash
# Configure JIRA credentials
jirtik --configure jira_email your@email.com
jirtik --configure jira_token your_jira_token

# Configure TickTick OAuth credentials
jirtik --configure ticktick_client_id your_client_id
jirtik --configure ticktick_client_secret 'your_client_secret'
```

Note: Use single quotes for values containing special characters.

## Usage

### Show Version
```bash
jirtik --version
# or
jirtik -v
```

### Create TickTick Task from JIRA Issue
```bash
# Basic usage
jirtik --jira-url https://your-domain.atlassian.net/browse/PROJECT-123

# With custom tags
jirtik --jira-url https://your-domain.atlassian.net/browse/PROJECT-123 --tags "work,important,urgent"
```

### Command Line Options

- `-v, --version`: Show the application version
- `-j, --jira-url URL`: JIRA issue URL to create TickTick task from
- `-t, --tags TAGS`: Comma-separated list of tags to add to the task (optional)
- `--configure KEY VALUE`: Configure credentials
  - Available keys: 
    - `jira_email`
    - `jira_token`
    - `ticktick_client_id`
    - `ticktick_client_secret`

## Features

- Automatically creates TickTick tasks from JIRA issues
- Transfers issue title and description
- Supports custom tags
- Automatically adds JIRA domain as a tag if no tags are specified
- Secure credential management

## Error Handling

If you encounter any errors, the tool will provide clear error messages, especially for:
- Missing TickTick OAuth credentials
- Invalid JIRA URLs
- Authentication issues
- Network connectivity problems

## Support

For issues and feature requests, please open an issue in the project repository.
