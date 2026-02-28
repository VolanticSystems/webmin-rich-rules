#!/usr/bin/perl
# ACL security definitions for firewalld-rich module

require 'firewalld-rich-lib.pl';

# Return HTML for access control form
sub acl_security_form
{
    my ($user) = @_;
    return "<p>No access control options for this module.</p>";
}

# Parse access control form data
sub acl_security_save
{
    my ($user, $in) = @_;
    return {};
}

1;
