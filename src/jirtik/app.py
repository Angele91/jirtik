import click
from rich.console import Console
from typing import Optional
from ._version import __version__
from jirtik.config_manager import ConfigManager
from jirtik.task_manager import TaskManager


# Initialize Rich console for pretty output
console = Console()


@click.group(invoke_without_command=True)
@click.pass_context
@click.option('-v', '--version', is_flag=True, help='Shows the app version.')
def cli(ctx, version):
    """
    Jirtik - A tool to create TickTick tasks from issue trackers like Jira, Gitea, etc.
    """
    # Initialize task manager
    ctx.ensure_object(dict)
    ctx.obj['task_manager'] = TaskManager()

    if ctx.invoked_subcommand is None:
        if version:
            console.print(f"[bold green]Jirtik v{__version__}[/]")
        else:
            click.echo(ctx.get_help())


@cli.command()
@click.option(
    '-u',
    '--url',
    type=str,
    required=True,
    help='Issue URL to create TickTick task from (supports Jira, Gitea, etc.).'
)
@click.option(
    '-t',
    '--tags',
    type=str,
    required=False,
    help='Comma-separated list of tags to add to the task. Example: work,important,urgent'
)
@click.pass_context
def create(ctx, url: str, tags: Optional[str] = None):
    """Create a TickTick task from an issue URL."""
    task_manager = ctx.obj['task_manager']

    try:
        # Ensure we have TickTick credentials
        config = ConfigManager()
        client_id = config.get_config("ticktick_client_id")
        client_secret = config.get_config("ticktick_client_secret")

        if not client_id or not client_secret:
            console.print(
                "[bold red]Error:[/] TickTick OAuth credentials not configured. "
                "Please run:\n"
                "  [bold yellow]jirtik configure ticktick_client_id YOUR_CLIENT_ID[/]\n"
                "  [bold yellow]jirtik configure ticktick_client_secret 'YOUR_CLIENT_SECRET'[/]"
            )
            return

        # Fetch issue details with animation
        with console.status("[bold blue]Fetching issue details...[/]", spinner="dots"):
            issue = task_manager.get_issue(url)

        # Process tags
        tag_list = []
        if tags:
            # Split comma-separated tags and strip whitespace
            tag_list = [tag.strip() for tag in tags.split(',')]
        else:
            # If no tags specified, use the domain tag from the provider
            with console.status("[bold blue]Generating tags...[/]", spinner="dots"):
                domain_tag = task_manager.extract_domain_tag(url)
                if domain_tag:
                    tag_list.append(domain_tag)

        task_description = f"URL: {url}\n\n{issue['description']}"

        # Create TickTick task with progress animation
        with console.status("[bold green]Creating TickTick task...[/]", spinner="dots"):
            task_manager.create_ticktick_task(
                title=issue["summary"],
                description=task_description,
                tags=tag_list,
            )

        console.print("[bold green]✓[/] TickTick task created successfully!")

    except Exception as e:
        console.print(f"[bold red]Error:[/] {str(e)}")


@cli.command()
@click.argument('key', type=str)
@click.argument('value', type=str)
@click.pass_context
def configure(ctx, key: str, value: str):
    """
    Configure credentials.

    Example: jirtik configure jira_email your@email.com
    """
    task_manager = ctx.obj['task_manager']
    config = ConfigManager()

    with console.status(f"[bold blue]Updating configuration for [cyan]{key}[/]...[/]", spinner="dots"):
        # Provider-specific configuration
        if key in task_manager.get_all_supported_config_keys():
            task_manager.set_provider_config(key, value)
        else:
            # Global configuration (TickTick, etc.)
            config.set_config(key, value)

    console.print(f"[bold green]✓[/] Configuration [cyan]{key}[/] updated successfully!")


@cli.command()
@click.pass_context
def show_config_keys(ctx):
    """Show all available configuration keys."""
    task_manager = ctx.obj['task_manager']

    config_keys = task_manager.get_all_supported_config_keys()
    config_keys.extend(["ticktick_client_id", "ticktick_client_secret"])

    console.print("[bold]Available configuration keys:[/]")
    for key in config_keys:
        console.print(f"  [cyan]{key}[/]")


def main():
    """Main entry point for the application."""
    return cli(obj={})


def square(x: int):
    """Calculate the square of a number."""
    y = x * x
    console.print(f"The square of {x} is [bold green]{y}[/]!")
    return y
