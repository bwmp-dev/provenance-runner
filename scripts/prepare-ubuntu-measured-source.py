#!/usr/bin/env python3
"""Normalize the accepted, already prepared pinned Ubuntu tree into a NEW archive.

Never fetch, extract, mount or mutate the source. Run after the exact accepted
OCI export/prepare recipe in a disposable protected root. Tree SHA verification
is mandatory; provenance is supplied separately by the export driver.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess

OCI = 'ubuntu:24.04@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517'
TREE = '55b3d6002a16c74e9f37638a451a4b4c32b4078b06377d85a8633b89c2506500'
EMPTY = {'dev/console': 'file', 'dev/shm': 'directory',
         'tmp/provenance-probe-events.ndjson': 'file'}
LINKS = {frozenset(('usr/bin/perl','usr/bin/perl5.38.2')),
         frozenset(('usr/bin/gunzip','usr/bin/uncompress'))}


def check(condition):
    if not condition:
        raise ValueError('prepared Ubuntu source identity or normalization refusal')


def tree_sha(root):
    p = subprocess.Popen(['tar','--sort=name','--format=gnu','--mtime=@0','--owner=0',
                          '--group=0','--numeric-owner','-cf','-','-C',str(root),'.'],
                         stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
    digest = hashlib.file_digest(p.stdout,'sha256').hexdigest()
    check(p.wait(timeout=30) == 0)
    return digest


def inspect(root):
    hardlinks = {}
    for base, dirs, files in os.walk(root, followlinks=False):
        for name in dirs+files:
            p = Path(base)/name
            s = p.lstat()
            check(stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode) or stat.S_ISLNK(s.st_mode))
            check(not s.st_mode & 0o6000)
            if stat.S_ISREG(s.st_mode) and s.st_nlink > 1:
                key = (s.st_dev,s.st_ino,s.st_nlink)
                hardlinks.setdefault(key,[]).append(str(p.relative_to(root)))
    check({frozenset(v) for v in hardlinks.values()} == LINKS)
    records=[]
    for (_,_,count),names in sorted(hardlinks.items()):
        check(count == len(names) == 2)
        hashes=[]
        for name in sorted(names):
            with (root/name).open('rb') as f:
                hashes.append(hashlib.file_digest(f,'sha256').hexdigest())
        check(len(set(hashes)) == 1)
        records.append({'paths':sorted(names),'sha256':hashes[0]})
    for name,kind in EMPTY.items():
        p=root/name
        s=p.lstat()
        check((stat.S_ISREG(s.st_mode) and s.st_size == 0 and s.st_nlink == 1)
              if kind == 'file' else (stat.S_ISDIR(s.st_mode) and not list(p.iterdir())))
    return records


def normalize(root, output, oci):
    check(oci == OCI and os.geteuid() == 0)
    check(root.is_absolute() and root.resolve() == root and root != Path('/'))
    check(output.is_absolute() and output.resolve() == output and not output.exists())
    check(output.parent != root and root not in output.parents)
    for p in (root,*root.parents,output.parent,*output.parent.parents):
        s=p.lstat()
        check(stat.S_ISDIR(s.st_mode) and s.st_uid == 0 and not s.st_mode & 0o022)
    opts=subprocess.run(['findmnt','--noheadings','--mountpoint',str(root),'--output','OPTIONS'],
                        check=True,capture_output=True,text=True).stdout.strip().split(',')
    check('ro' in opts and tree_sha(root) == TREE)
    links=inspect(root)
    fd=os.open(output,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o400)
    try:
        with os.fdopen(fd,'wb') as f:
            subprocess.run(['tar','--sort=name','--format=gnu','--mtime=@0','--owner=0','--group=0',
                            '--numeric-owner','--hard-dereference',
                            *['--exclude=./'+n for n in EMPTY],'-cf','-','-C',str(root),'.'],
                           stdout=f,stderr=subprocess.DEVNULL,check=True,timeout=60)
            f.flush()
            os.fsync(f.fileno())
        check(tree_sha(root) == TREE and inspect(root) == links)
        with output.open('rb') as f:
            digest=hashlib.file_digest(f,'sha256').hexdigest()
        return {'version':1,'sourceOCI':OCI,'preparedTreeSha256':TREE,
                'archiveSha256':digest,'archiveBytes':output.stat().st_size,
                'removedEmptyPlaceholders':sorted(EMPTY),'dereferencedHardlinks':links,
                'sourceUnchanged':True}
    except BaseException:
        output.unlink()
        raise


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--source-oci',required=True)
    a=parser.parse_args()
    print(json.dumps(normalize(a.root,a.output,a.source_oci),sort_keys=True))
