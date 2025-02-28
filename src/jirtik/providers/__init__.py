"""
Issue providers for jirtik.
"""
from .jira import JiraProvider
from .gitea import GiteaProvider

# List of all available providers
AVAILABLE_PROVIDERS = [JiraProvider, GiteaProvider]
