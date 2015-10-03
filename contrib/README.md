github-merge.sh
==================

A small script to automate merging pull-requests securely and sign them with GPG.

For example:

  ./github-merge.sh digitalbitbox/mcu 3077

(in any git repository) will help you merge pull request #3077 for the
digitalbitbox/mcu repository.

What it does:
* Fetch master and the pull request.
* Locally construct a merge commit.
* Show the diff that merge results in.
* Ask you to verify the resulting source tree (so you can do a make
check or whatever).
* Ask you whether to GPG sign the merge commit.
* Ask you whether to push the result upstream.

This means that there are no potential race conditions (where a
pullreq gets updated while you're reviewing it, but before you click
merge), and when using GPG signatures, that even a compromised github
couldn't mess with the sources.

Setup
---------
Configuring the github-merge tool for the digitalbitbox/mcu repository is done in the following way:

    git config githubmerge.repository digitalbitbox/mcu
    git config githubmerge.testcmd "make -j4 check" (adapt to whatever you want to use for testing)
    git config --global user.signingkey mykeyid (if you want to GPG sign)


signature_check.sh
==================

Validate signatures on each and every commit within the given range.

For example:

  ./signature_check.sh f0a012e224fedac87b0393a161d4af1473fea74a

Returns commits with unsigned or untrusted signature.
