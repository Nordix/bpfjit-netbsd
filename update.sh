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
     --path-rename sys/:src/ \
     --force \
     || die "Failed to rewrite history using git-filter-repo"

# Prepare to overwrite our own repo.
cd $reporoot

# Make a backup of our ".git"
tar -cjf "_update/gitbackup$(date +%Y-%m-%d).tar.bz2" .git

# Remove current bpfjit files from our own repo.
# TODO: Remove --force flag, but this requires a fresh clone
$gfr --invert-paths \
     --path src/net/bpf.h --path src/net/bpfjit.c --path src/net/bpfjit.h \
     --force \
    || die "Failed to rewrite history using git-filter-repo"

# Merge latest bpfjit files to our own repo.
git remote remove netbsd
git remote add netbsd _update/netbsd-src \
    || die "Failed to add 'netbsd-src' remote repo"
git fetch netbsd --tags \
    || die "Failed to fetch remote repo 'netbsd-src'"
git merge -m "Merge bpfjit from NetBSD" \
    --allow-unrelated-histories netbsd/trunk \
    || die "Failed to merge remote repo 'netbsd-src'"
git remote remove netbsd \
    || die "Failed to remove 'netbsd-src' remote repo"

# Patch bpfjit files to compile.
# Remove unused includes
sed -i 's|\(#include <net/dlt.h>\)|/* \1 */|g' src/net/bpf.h
sed -i 's|\(#include <sys/ioccom.h>\)|/* \1 */|g' src/net/bpf.h
sed -i 's|\(#include <pcap-bpf.h>\)|/* \1 */|g' src/net/bpfjit.h
# Remove assert using unknown macro
sed -i 's|\(__CTASSERT.*\)$|/* \1 */|g' src/net/bpf.h
# Ignore unknown macro __RCSID
sed -i 's|^__RCSID|#define __RCSID(s)\n__RCSID|g' src/net/bpfjit.c
# Updates needed for latest version of sljit
sed -i 's/sljit_emit_ijump/sljit_emit_icall/g' src/net/bpfjit.c
sed -i 's/SLJIT_CALL2,/SLJIT_CALL, SLJIT_ARG1(SW) | SLJIT_ARG2(SW),/g' src/net/bpfjit.c
sed -i 's/SLJIT_CALL3,/SLJIT_CALL, SLJIT_ARG1(SW) | SLJIT_ARG2(SW) | SLJIT_ARG3(SW),/g' src/net/bpfjit.c
sed -i 's/sljit_create_compiler(NULL)/sljit_create_compiler(NULL, NULL)/g' src/net/bpfjit.c
sed -i 's/sljit_emit_enter(compiler, 0, 2,/sljit_emit_enter(compiler, 0, SLJIT_ARG1(SW) | SLJIT_ARG2(SW),/g' src/net/bpfjit.c
sed -i 's/sljit_free_code((void \*)code)/sljit_free_code((void *)code, NULL)/g' src/net/bpfjit.c

# Commit patched files.
git add src/net/bpf.h src/net/bpfjit.h src/net/bpfjit.c \
    && git commit -m "Patch bpfjit to build with latest sljit" \
        || die "Failed to commit patch"

echo "Done."
