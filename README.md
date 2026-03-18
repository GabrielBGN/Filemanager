# Filemanager
A simple file system implemented in C that simulates disk storage using a custom disk image and fixed-size blocks.

Features:
-Create, format, and manage a virtual disk

-Store and retrieve files (Put / Get)

-File operations: Rename, Remove, Link, Unlink

-Flat directory structure using a File Name Table

-Block allocation with bitmap tracking

To run: gcc -O2 -Wall -Wextra -std=c11 fs.c -o FS

./FS

Comands: Createfs, Openfs, Formatfs, Put, Get, List,
Rename, Remove, Link, Unlink, Quit

Author:
Gabriel Balogun
Computer Science Student – UTA
