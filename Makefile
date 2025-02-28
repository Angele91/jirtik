publish-local:
	cd publish && ./publish_local.sh

publish: publish-local

# Run jirtik with parameters
# Usage examples:
#   make run URL=https://jira.example.com/browse/PROJ-123  # Create task from Jira issue
#   make run URL=https://gitea.example.com/user/repo/issues/123  # Create task from Gitea issue
#   make run URL=https://jira.example.com/browse/PROJ-123 TAGS=work,important  # With tags
#   make run VERSION=true  # Show version
#   make run CONFIG_KEY=jira_email CONFIG_VALUE=your@email.com  # Configure Jira credentials
#   make run CONFIG_KEY=gitea_username CONFIG_VALUE=username  # Configure Gitea credentials
#   make run CONFIG_KEY=gitea_token CONFIG_VALUE=token123  # Configure Gitea token
run:
ifdef URL
ifdef TAGS
	jirtik create --url "$(URL)" --tags "$(TAGS)"
else
	jirtik create --url "$(URL)"
endif
else ifdef VERSION
	jirtik --version
else ifdef CONFIG_KEY
ifdef CONFIG_VALUE
	-jirtik configure $(CONFIG_KEY) "$(CONFIG_VALUE)" || true
else
	@echo "Error: CONFIG_VALUE must be specified with CONFIG_KEY"
	@echo "Usage: make run CONFIG_KEY=key CONFIG_VALUE=value"
endif
else
	@echo "Usage:"
	@echo "  make run URL=https://jira.example.com/browse/PROJ-123           # Create task from Jira issue"
	@echo "  make run URL=https://gitea.example.com/user/repo/issues/123     # Create task from Gitea issue"
	@echo "  make run URL=https://jira.example.com/browse/PROJ-123 TAGS=work,important  # With tags"
	@echo "  make run VERSION=true                                           # Show version"
	@echo "  make run CONFIG_KEY=jira_email CONFIG_VALUE=your@email.com      # Configure Jira credentials"
	@echo "  make run CONFIG_KEY=jira_token CONFIG_VALUE=your-token          # Configure Jira token"
	@echo "  make run CONFIG_KEY=gitea_username CONFIG_VALUE=username        # Configure Gitea username"
	@echo "  make run CONFIG_KEY=gitea_token CONFIG_VALUE=token123           # Configure Gitea token"
endif
