gdrive_pycli
============

Google Drive Python Client

This is a really simple basic python client which uses the google drive api, to view quota storage usage breakup , dump the file list, and also downloda a specific folder from Google Drive locally. The script is really designed for use in a Linux environment, though it should be portable to other distros.


Installation
============

This requires the google api python library. This can be installed using easy_isntall, run as root:
easy_install-2.7 google-api-python-client
In order to view usage breakup, the ncdu command is required. This should be available on your distro or download from : http://dev.yorhel.nl/ncdu


Basic Usage
============

During the first usage, authorization will be required. Please visit the specified link, and Accept the authorization. Paste the code that you obtain, back into the program.

For large number files on google drive, it is preferred to dump the filelist with all metadata locally to cache and speed up future commands. For this purpose dump the filesystem locally:

```
./drive_pycli.py dumpfs -d gdrive_fs.gz
```

Now for all future commands use "-f gdrive_fs.gz" to avoid redownloading the filelisting from google drive each time. If your google drive files are updated, you will need to redownload to get the new listing.

View Quota Usage
================

This tool allows you to view your quota usage, using a nice ncurses interface provided by an external program ncdu (which is intended for viewing local disk usage). To view usage:

```
./drive_pycli.py [-f gdrive_fs.gz] usage  | ncdu  -f-
./drive_pycli.py [-f gdrive_fs.gz] usage -n gdrive_fs.ncdu.dump; ncdu  -f gdrive_fs.ncdu.dump;
```

The second version allows you to run ncdu separately on the dump file as many times as you want in a faster cached manner.


View Filelist
=============

To view the filelist in a find like file listing. use the filelist command. Additionally you can add the --md5 or --fid flags to  also display md5sums of files and google drive file IDs. The md5sums are useful to detect duplicates. The fid flag is useful to later download a specific folder using the download command.


```
./drive_pycli filelist [--md5] [--fid] > gdrive_filelist
less gdrive_filelist
```


Download Folder
===============

You can download an entire google drive folder using the download command. Find out the specific folder's fid by using the filelist command. You can then download the entire directory

```
./drive_pycli download [-f gdrive_fs.gz] --download '0B8m4-somebigrandomstrfromfilelist'
```
