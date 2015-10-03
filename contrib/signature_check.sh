#!/bin/sh
#
# Validate signatures on each and every commit within the given range
##

# if a ref is provided, append range spec to include all children
chkafter="${1+$1..}"


# Check every commit after chkafter (or all commits if chkafter was not
# provided) for a trusted signature, listing invalid commits. %G? will output
# "G" if the signature is trusted.
git log --pretty="format:%H   %aN   %s   %G?" "${chkafter:-HEAD}" \
  | grep -v "${t} G$"

# grep will exit with a non-zero status if no matches are found, which we
# consider a success, so invert it
[ $? -gt 0 ]
