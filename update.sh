#!/bin/sh

# Updates the repo from NetBSD's mirror on GitHub
# -----------------------------------------------
#
# NOTE!
#
# This script downloads the NetBSD repo which is several gibabytes. The history
# and contents will be destructively rewritten using git-filter-repo. To avoid
# downloading the repo each time, the script attempts to backup the repo before
# destructively rewriting it. The backup file, if not deleted, is automatically
# used and updated the next time this script is used.

die() { echo "$*" 1>&2 ; exit 1; }

# python3 required by git-filter-repo
which python3 > /dev/null || die "python3 not found in path"

cd $(dirname $0)
reporoot=$(pwd)
mkdir -p _update
cd _update || die "Can't cd to _update directory"

# Look for git-filter-repo in path or clone it.
gfr=$(which git-filter-repo)
if [ $? -ne 0 ]
then
    echo "Cloning git@github.com:newren/git-filter-repo."
    git clone git@github.com:newren/git-filter-repo \
        || die "Can't clone git-filter-repo"
    gfr=$(pwd)/git-filter-repo/git-filter-repo
fi

# Clone NetBSD. Update using git pull if clone already exists.
if [ -d netbsd-src ] ; then
    die "Directory netbsd-src already existing. Aborting."
elif [ -e netbsd-src.tar.bz2 ] ; then
    echo "Restoring compressed copy of netbsd-src repo."
    # Found compressed copy of NetBSD repo from previous run of this script.
    # Use it, update it using git pull and package copy again.
    tar -xf netbsd-src.tar.bz2
    cd netbsd-src    || die "Failed to restore netbsd-src repo backup."
    # Only the .git directory is backed up. Reset --hard restores the files.
    git reset --hard || die "Failed to restore files in netbsd-src repo."
    git pull         || die "Failed to update netbsd-src using git pull."
    cd ..
else
    # Clone the huge repo. Only tracking the main branch (trunk) may limit the
    # download size a little.
    echo "Cloning NetBSD/src. This may take some time..."
    echo "git clone git@github.com:NetBSD/src --single-branch netbsd-src"
    git clone git@github.com:NetBSD/src --single-branch netbsd-src \
        || die "Failed to clone git@github.com:NetBSD/src"

    # Make a backup so we don't have to download it again next time.
    tar -cjf netbsd-src.tar.bz2 netbsd-src/.git \
        || die "Failed to backup current repo"
fi

# Rewrite the history, keeping only the bpfjit files.
# Forced rewrite needed when using a restored netbsd repo.
cd netbsd-src
$gfr --path sys/net/bpf.h --path sys/net/bpfjit.c --path sys/net/bpfjit.h \
     --path-rename sys/net/:src/ \
     --force \
     || die "Failed to rewrite history using git-filter-repo"

# Prepare to overwrite our own repo.
cd $reporoot

# Make a backup of our ".git"
tar -cjf "_update/gitbackup$(date +%Y-%m-%d).tar.bz2" .git
rm -rf .git src \
    && mv _update/netbsd-src/.git _update/netbsd-src/src . \
    && rmdir _update/netbsd-src \
        || die "Failed to replace our repo with the filtered netbsd-src repo"

# Add this script, README, etc. as a commit on top of everything.
git add src README.md update.sh .gitignore \
    && git commit -m "Update bpfjit from NetBSD" \
        || die "Failed to commit update"

echo "Done."
