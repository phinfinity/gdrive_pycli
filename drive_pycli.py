#!/usr/bin/env python2
# Author Phinfinity <rndanish@gmail.com>
# do easy_install-2.7 google-api-python-client before running for dependencies

import argparse
from hashlib import md5
import gzip
import json
import os
import string
import sys
import time
import urllib2

from apiclient.discovery import build
from httplib2 import Http
from oauth2client.client import OAuth2Credentials
from oauth2client.client import OAuth2WebServerFlow

GOOG_DIR_MIME = 'application/vnd.google-apps.folder'

TOKENFILE = os.path.expanduser("~/.gdrive_pycli_token")
DUMPFSTOFILE = None
READFSFROMFILE = None
NCDU_DUMP_FILE = None
SKIP_NON_OWNED = True
COMMAND = None
PRINT_MD5 = False
PRINT_FID = False
DOWNLOAD_FID = None
DOWNLOAD_DIR = None

def set_constants_from_args():
    global TOKENFILE, DUMPFSTOFILE, READFSFROMFILE, NCDU_DUMP_FILE
    global SKIP_NON_OWNED, COMMAND, PRINT_MD5, PRINT_FID, DOWNLOAD_FID
    global DOWNLOAD_DIR
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices = ['usage','dumpfs','filelist','download'],
            help="usage: Display usage information, using external ncdu viewer.\
                    dumpfs: Dump google drive fs info to local file, to speedup other commands.\
                    filelist: Dump the gdrive fs in a find like human readable list.")
    parser.add_argument("-d", "--dump-fs", type=str, default=None,
            help="Specify a file to dump the google drive File listing\
                    to a gzip compressed local file from the internet")
    parser.add_argument("-f", "--read-fs", type=str, default=None,
            help="Specify path to a local compressed file created using -d\
                    to load the google drive file listing from, isntead of\
                    fetching from the internet again.")
    parser.add_argument("-t", "--token-file", type=str, default=TOKENFILE,
            help="Path to the token file used for authorization credential\
                    store. Defaults to %s" % TOKENFILE)
    parser.add_argument("-n", "--ncdu-dump-file", type=str, default=None,
            help="File to dump the NCDU formatted space usage data to. \
                    This file can be used by ncdu to display usage breakup")
    parser.add_argument("--include-shared", action="store_true",
            help="Add this flag to include all shared files. By default only files\
                    which you own are included for processing.")
    # Only for filelist command (TODO: use subparsers)
    parser.add_argument("--md5", action="store_true", help="include md5sums for filelist command")
    parser.add_argument("--fid", action="store_true", help="include gdrive file id for filelist command")
    # Only for download command (TODO: use subparsers)
    parser.add_argument("--download", type=str, help="Specify google drive file ID (from filelist) to download. \
            If this is a shared entity, make sure to use --include-shared")
    parser.add_argument("--dir", type=str, default=".",
            help="Specify folder to save to for download command. Defaults to current directory")

    args = parser.parse_args()
    COMMAND = args.command
    DUMPFSTOFILE = args.dump_fs
    READFSFROMFILE = args.read_fs
    TOKENFILE = args.token_file
    NCDU_DUMP_FILE = args.ncdu_dump_file
    PRINT_MD5 = args.md5
    PRINT_FID = args.fid
    DOWNLOAD_FID = args.download
    DOWNLOAD_DIR = args.dir
    if (COMMAND == "dumpfs") and (DUMPFSTOFILE is None):
        sys.stderr.write("Error!: Cannot do dumpfs without specifying path to dump using -d flag\n")
        sys.exit(1)
    if (DUMPFSTOFILE is not None) and (READFSFROMFILE is not None):
        sys.stderr.write("Error!: Cannot set both dump file and readfile. Only one can be used\n")
        sys.exit(1)
    if args.include_shared:
        SKIP_NON_OWNED = False
    if (COMMAND == "download") and (DOWNLOAD_FID is None):
        sys.stderr.write("Error!: Must specify --download file ID to be downloaded\n")
        sys.exit(1)


DEFAULT_DRIVE_API_SERVICE = None
DEFAULT_DRIVE_API_HTTP = Http()
DEFAULT_DRIVE_API_CRED = None

def get_local_token():
    if (not os.path.exists(TOKENFILE)):
        return None
    try:
        f = open(TOKENFILE, 'r')
        cred_json = f.read()
        f.close()
        cred = OAuth2Credentials.from_json(cred_json)
        cred.refresh(DEFAULT_DRIVE_API_HTTP)
        return cred
    except Exception as e:
        sys.stderr.write("Failed to Read auth from local file, re doing Auth (Error: %s)\n" % str(e))
        return None

def do_auth():
    global DEFAULT_DRIVE_API_CRED
    if DEFAULT_DRIVE_API_CRED is not None:
        return DEFAULT_DRIVE_API_CRED
    cred = get_local_token()
    if cred is None:
        flow = OAuth2WebServerFlow(
                client_id='310652837554-glpvnkv4j89t8var3vfav9aorl8fslge.apps.googleusercontent.com',
                client_secret='MUcgkLAH4-vdsPIFdAO5ATEL',
                scope='https://www.googleapis.com/auth/drive.readonly',
                redirect_uri='urn:ietf:wg:oauth:2.0:oob')
        sys.stderr.write("Please Visit the following link and paste the code :\n" + flow.step1_get_authorize_url() + "\n")
        sys.stderr.write("Enter Code : ")
        code = raw_input()
        cred = flow.step2_exchange(code)
    json = cred.to_json()
    f = open(TOKENFILE, 'w')
    f.write(json)
    f.close()
    DEFAULT_DRIVE_API_CRED = cred
    return cred

def get_drive_service():
    global DEFAULT_DRIVE_API_SERVICE, DEFAULT_DRIVE_API_HTTP
    if DEFAULT_DRIVE_API_SERVICE is None:
        cred = do_auth()
        DEFAULT_DRIVE_API_HTTP = cred.authorize(DEFAULT_DRIVE_API_HTTP)
        DEFAULT_DRIVE_API_SERVICE = build('drive', 'v2', http=DEFAULT_DRIVE_API_HTTP)
    return DEFAULT_DRIVE_API_SERVICE

def list_all_files(fname=None):
    sys.stderr.write("Getting authorization... \n")
    serv = get_drive_service()
    drive_files = serv.files()
    req = drive_files.list(maxResults=1000)
    all_files = []
    while req is not None:
        sys.stderr.write("Fetching file list... \n")
        resp = req.execute()
        all_files.extend(resp['items'])
        req = drive_files.list_next(req, resp)
        sys.stderr.write("%d items received\n" % len(all_files))
    sys.stderr.write("%d items received in total\n" % len(all_files))
    if fname is not None:
        f = gzip.open(fname, 'w')
        json.dump(all_files, f)
        f.close()
    return all_files

def get_fs_from_file(fname):
    sys.stderr.write("Reading fs from file %s\n" % fname)
    sys.stderr.flush()
    f = gzip.open(fname, 'r')
    o = json.load(f)
    f.close()
    return o

class Node:
    def __init__(self, fsentry=None, make_root=None):
        if fsentry is not None:
            self.fid = fsentry['id']
            self.sz = int(fsentry['quotaBytesUsed'])
            self.mime = fsentry['mimeType']
            self.isdir = (self.mime == GOOG_DIR_MIME)
            self.istrashed = fsentry['labels']['trashed']
            self.name = fsentry['title']
            self.role = fsentry['userPermission']['role']
            process_parent = lambda p: "root" if p['isRoot'] else p["id"]
            self.parents = map(process_parent , fsentry["parents"])
            if self.isdir:
                self.children = []
            self.md5 = "NOSUMAVL" if 'md5Checksum' not in fsentry else fsentry['md5Checksum']
        elif make_root is True:
            self.fid = "root"
            self.sz = 0
            self.mime = GOOG_DIR_MIME
            self.isdir = True
            self.istrashed = False
            self.name = "root"
            self.role = "owner"
            self.parents = []
            self.children = []
            self.md5 = "NOSUMAVL"
        else:
            raise TypeError("Invalid Node constructor")
    def __repr__(self):
        return str(
                (self.fid, self.sz, self.mime,
                    "Dir" if self.isdir else "File",
                    "Trash" if self.istrashed else "NoTrash",
                    self.role, self.parents, self.name, "["+self.md5+"]"))


def simplify_fs(big_fs):
    big_fs = map(Node, big_fs)

    if SKIP_NON_OWNED:
        big_fs = filter(lambda x: x.role == "owner", big_fs)

    d = {}
    for entry in big_fs:
        d[entry.fid] = entry
    d["root"] = Node(make_root = True)

    for entry in big_fs:
        for parent in entry.parents:
            if parent not in d:
                sys.stderr.write("Unknown parent : %s for entry : %s\n" % (parent, entry))
            else:
                d[parent].children.append(entry.fid)
        entry.parents = filter(lambda x: x in d, entry.parents)

    rootEntries = filter(lambda x: len(d[x].parents)==0, d)
    return (d, rootEntries)

def make_ncdu_dump(d, rootEntries):
    processed_ids = set()

    def make_file_entry(name, size):
        return {"name": name, "asize": size, "dsize": size}

    def process_node(n):
        if not d[n].isdir:
            return make_file_entry(d[n].name, d[n].sz)
        ret = [make_file_entry(d[n].name, 0)]
        if n in processed_ids:
            return ret
        else:
            processed_ids.add(n)
            for c in d[n].children:
                ret.append(process_node(c))
            return ret
    fs = [make_file_entry("Google Drive", 0)]
    for rnod in rootEntries:
        fs.append(process_node(rnod))
    fs = [1,0,{"progname":"drive_pycli", "progver": "1.0", "timestamp": time.time()}, fs]
    return json.dumps(fs, indent=2)

def print_file_list(d, rootEntries):
    processed_ids = set()
    print_node = lambda x,prefix: "%s/%s\t%db" % (prefix, x.name, x.sz)
    if PRINT_MD5:
        if PRINT_FID:
            print_node = lambda x,prefix: "%s/%s\t%db\t[%s]\t{%s}" % (prefix, x.name, x.sz, x.md5, x.fid)
        else:
            print_node = lambda x,prefix: "%s/%s\t%db\t[%s]" % (prefix, x.name, x.sz, x.md5)
    elif PRINT_FID:
            print_node = lambda x,prefix: "%s/%s\t%db\t{%s}" % (prefix, x.name, x.sz, x.fid)

    print_dir = lambda x,prefix: "%s/%s/" % (prefix, x.name)
    if PRINT_FID:
        print_dir = lambda x,prefix: "%s/%s/\t{%s}" % (prefix, x.name, x.fid)


    def process_node(n, prefix=""):
        if not d[n].isdir:
            print print_node(d[n], prefix).encode('utf-8')
            return
        else:
            print print_dir(d[n], prefix).encode('utf-8')
            

        if n in processed_ids:
            return 
        else:
            processed_ids.add(n)
            for c in d[n].children:
                process_node(c, prefix + "/" + d[n].name)
            return 

    for rnod in rootEntries:
        process_node(rnod)

def do_download(d):
    valid_fname_chars = "-_.()[]{} '#$%%&+,:;%s%s" % (string.ascii_letters, string.digits)
    make_valid_fname = lambda x: ''.join(c for c in x if c in valid_fname_chars)

    http = DEFAULT_DRIVE_API_HTTP
    cred = do_auth()
    auth_headers = {}
    cred.apply(auth_headers)
    serv = get_drive_service()
    get_metadata_request = serv.files().get
    def human_readable(num):
        for x in ['bytes','KB','MB','GB','TB']:
            if num < 1024.0:
                return "%3.1f %s" % (num, x)
            num /= 1024.0

    def md5_local_file(fname):
        m = md5()
        CHUNK = 65536
        with open(fname, 'rb') as f:
            buf = f.read(CHUNK)
            while len(buf) > 0:
                m.update(buf)
                buf = f.read(CHUNK)
        return m.hexdigest()

    def download_file(fid, dirpath, fname):
        fname = make_valid_fname(fname)
        if (len(fname) == 0) or fname == "." or fname == "..":
            return
        fname = os.path.join(dirpath, fname)
        print "Downloading (%s) to %s" % (fid, fname) 
        sys.stderr.write("Fetching meta data for %s\n" % fname)
        metadata = get_metadata_request(fileId=fid).execute()
        sys.stderr.write("Got metadata, begining download\n")
        if ('downloadUrl' not in metadata) or ('md5Checksum' not in metadata) or ('fileSize' not in metadata):
            sys.stderr.write("Skipping Non-Contentfile : %s\n" % fname)
            with open(fname, 'w') as f:
                f.write("Google Drive File Id: %s\nFilename: %s\n" % (fid, metadata['title']))
                if 'alternateLink' in metadata:
                    f.write("Link: %s\n" % metadata['alternateLink'])
            return
        else:
            l = metadata['downloadUrl']
            md5 = metadata['md5Checksum']
            sz = int(metadata['fileSize'])
            EXISTS = False
            if os.path.exists(fname):
                EXISTS = True
                if os.path.getsize(fname) != sz:
                    EXISTS = False
                elif md5_local_file(fname) != md5:
                    EXISTS = False
            if EXISTS:
                sys.stderr.write("Skipping %s as already exists with same md5\n" % fname)
                return
            req = urllib2.Request(l, headers=auth_headers)
            resp = urllib2.urlopen(req)
            CHUNK = 16*1024
            start_time = time.time()
            with open(fname, 'w') as f:
                while True:
                    chunk = resp.read(CHUNK)
                    if not chunk:
                        break
                    f.write(chunk)
                    speed = human_readable(f.tell()/(time.time()-start_time))+"/s"
                    sys.stderr.write("\r%s of %s : %s [%s]    " % (human_readable(f.tell()), human_readable(sz), fname, speed))
                sys.stderr.write("\n")

    if not os.path.exists(DOWNLOAD_DIR):
        os.makedirs(DOWNLOAD_DIR)

    processed_ids = set()
    download_list = []
    def process_node(n, prefix):
        if not d[n].isdir:
            download_list.append((d[n].fid, prefix, d[n].name))
            return

        prefix = os.path.join(prefix, make_valid_fname(d[n].name))
        if not os.path.exists(prefix):
            os.makedirs(prefix)

        if n in processed_ids:
            return 
        else:
            processed_ids.add(n)
            for c in d[n].children:
                process_node(c, prefix)
            return 

    process_node(DOWNLOAD_FID, DOWNLOAD_DIR)
    sys.stderr.write("%d Files to be downloaded\n" % len(download_list))
    for i in xrange(len(download_list)):
        sys.stderr.write("Downlodaing %d/%d\n" % (i+1, len(download_list)))
        download_file(*download_list[i])

def main():
    set_constants_from_args()
    drive_fs = None
    if READFSFROMFILE is None:
        drive_fs = list_all_files(DUMPFSTOFILE)
    else:
        drive_fs = get_fs_from_file(READFSFROMFILE)
    if COMMAND == "dumpfs":
        return # because you are already done
    (fs_id_dict, root_entries) = simplify_fs(drive_fs)
    
    if COMMAND == "usage":
        ncdump = make_ncdu_dump(fs_id_dict, root_entries)
        if NCDU_DUMP_FILE is None:
            print ncdump
        else:
            f = open(NCDU_DUMP_FILE, 'w')
            f.write(ncdump)
            f.close()
    elif COMMAND == "dumpfs":
        pass # Already done above
    elif COMMAND == "filelist":
        print_file_list(fs_id_dict, root_entries)
    elif COMMAND == "download":
        do_download(fs_id_dict)


if __name__ == "__main__":
    main()
