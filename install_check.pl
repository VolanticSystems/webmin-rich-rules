# install_check.pl
# Check if firewalld with rich rules support is installed

do 'firewalld-rich-lib.pl';

# is_installed(mode)
# For mode 0, returns 1 if installed, 0 if not
# For mode 1, returns 2 if installed and running,
#   1 if installed but not running, or 0 if not installed
sub is_installed
{
my ($mode) = @_;
return 0 if (!&check_firewalld_installed());
return 0 if (!&rich_rules_supported());
if ($mode) {
	return &is_firewalld_running() ? 2 : 1;
	}
return 1;
}

1;
