import argparse
from ._version import __version__
from my_app.config_manager import ConfigManager
from my_app.task_manager import TaskManager


DEFAULT_PARSER = argparse.ArgumentParser()


def main(parser=DEFAULT_PARSER):
    """Main entry point for the application."""
    parser.add_argument(
        "-v", "--version", action="store_true", help="Shows the app version."
    )
    parser.add_argument(
        "-s", "--square", type=int, required=False, help="Square a number."
    )
    parser.add_argument(
        "-j",
        "--jira-url",
        type=str,
        required=False,
        help="JIRA issue URL to create TickTick task from.",
    )
    parser.add_argument(
        "--configure",
        nargs=2,
        metavar=("KEY", "VALUE"),
        help="Configure credentials. Example: jirtik configure jira_email "
        "your@email.com\n"
        "Available keys: jira_email, jira_token, ticktick_client_id, "
        "ticktick_client_secret",
    )

    args = parser.parse_args()

    if args.configure:
        key, value = args.configure
        config = ConfigManager()
        config.set_config(key, value)
        return f"Configuration {key} updated successfully"

    if args.version:
        return __version__
    elif args.square:
        return square(args.square)
    elif args.jira_url:
        task_manager = TaskManager()
        try:
            # Ensure we have TickTick credentials
            config = ConfigManager()
            client_id = config.get_config("ticktick_client_id")
            client_secret = config.get_config("ticktick_client_secret")
            if not client_id or not client_secret:
                return (
                    "Error: TickTick OAuth credentials not configured. "
                    "Please run:\n"
                    "  jirtik --configure ticktick_client_id YOUR_CLIENT_ID\n"
                    "  jirtik --configure ticktick_client_secret "
                    "'YOUR_CLIENT_SECRET'"
                )

            # Get JIRA issue details
            issue = task_manager.get_jira_issue(args.jira_url)

            # Extract domain for tag
            tag = task_manager._extract_domain_tag(args.jira_url)

            # Create TickTick task
            task_manager.create_ticktick_task(
                title=issue["summary"],
                description=issue["description"],
                tag=tag
            )
            return "TickTick task created successfully"
        except Exception as e:
            return f"Error: {str(e)}"
    else:
        return (
            "Usage:\n"
            "  jirtik -v, --version        Show version\n"
            "  jirtik -s, --square N       Calculate square of a number\n"
            "  jirtik -j, --jira-url URL   Create TickTick task from JIRA "
            "issue\n"
            "  jirtik --configure KEY VALUE Configure credentials\n"
            "                              Available keys: jira_email, "
            "jira_token,\n"
            "                              ticktick_client_id, "
            "ticktick_client_secret\n"
            "                              Example: jirtik configure "
            "jira_email your@email.com\n"
            "                              For values with special chars use "
            "single quotes:\n"
            "                              jirtik --configure key 'value!@#$'"
        )


def square(x: int):
    """Calculate the square of a number."""
    y = x * x
    print(f"The square of {x} is {y}!")
    return y
