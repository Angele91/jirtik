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
# Configure JIRA credentials (you can add multiple emails for different JIRA instances)
jirtik --configure jira_email your@email1.com
jirtik --configure jira_email your@email2.com

# Configure JIRA tokens (you can add multiple tokens for different JIRA instances)
jirtik --configure jira_token your_jira_token_1
jirtik --configure jira_token your_jira_token_2

# Configure TickTick OAuth credentials
jirtik --configure ticktick_client_id your_client_id
jirtik --configure ticktick_client_secret 'your_client_secret'
```

Note: Use single quotes for values containing special characters.

### Multiple JIRA Credentials Support

Jirtik supports using multiple JIRA emails and tokens for different JIRA instances. When you configure multiple emails and tokens, Jirtik will:

1. Try each email-token combination sequentially when accessing a JIRA instance
2. Cache successful credential combinations in `~/.jirtik/jira_token_map.json`
3. Use the cached credentials for future requests to the same domain
4. Automatically try other combinations if cached credentials stop working

This feature is particularly useful if you:
- Work with multiple JIRA instances (e.g., different organizations)
- Have multiple JIRA accounts with different permissions
- Need to access both cloud and self-hosted JIRA instances
- Use different credentials for different JIRA domains

The credentials mapping cache helps optimize performance by remembering which email-token combination works for each JIRA domain, reducing the number of authentication attempts needed.

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
    - `jira_email`: Your JIRA account email (can be configured multiple times)
    - `jira_token`: JIRA API token (can be configured multiple times)
    - `ticktick_client_id`: TickTick OAuth client ID
    - `ticktick_client_secret`: TickTick OAuth client secret

## Features

- Automatically creates TickTick tasks from JIRA issues
- Transfers issue title and description
- Supports custom tags
- Automatically adds JIRA domain as a tag if no tags are specified
- Secure credential management
- Multiple JIRA credentials support with automatic mapping
- Smart credential caching for improved performance

## Error Handling

If you encounter any errors, the tool will provide clear error messages, especially for:
- Missing TickTick OAuth credentials
- Invalid JIRA URLs
- Authentication issues
- Network connectivity problems
- Credential authentication failures

## Support

For issues and feature requests, please open an issue in the project repository.
