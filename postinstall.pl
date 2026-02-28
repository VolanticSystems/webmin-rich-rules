# postinstall.pl
# Called by Webmin after module installation via foreign_call($m, "module_install")

do 'firewalld-rich-lib.pl';

sub module_install
{
# Ensure CGI files are executable
my $dir = $module_root_directory;
foreach my $cgi (glob("$dir/*.cgi")) {
	chmod(0755, $cgi);
}

# Ensure lang directory exists
my $lang_dir = "$dir/lang";
if (!-d $lang_dir) {
	mkdir($lang_dir, 0755);
}

# Ensure images directory exists
my $img_dir = "$dir/images";
if (!-d $img_dir) {
	mkdir($img_dir, 0755);
}
}

1;
