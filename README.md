# Mini File System (C)
A lightweight file system implemented in C that simulates disk storage using a custom disk image and fixed-size blocks. This project demonstrates core operating system concepts such as block allocation, file metadata management, and low-level file I/O.

Features:

-Designed and implemented a virtual disk using fixed-size blocks (256 bytes)

-Built a file management system supporting create, read, update, and delete operations

-Implemented file operations including Rename, Remove, Link, and Unlink

-Developed a flat directory structure using a File Name Table (FNT)

-Managed storage allocation using a bitmap for efficient tracking of free and used blocks

-Structured file metadata using an inode-like system (DABPT and BPT)

Build and Run:

gcc -O2 -Wall -Wextra -std=c11 fs.c -o FS
./FS

Comands: 

Createfs, Openfs, Formatfs, Put, Get, List,
Rename, Remove, Link, Unlink, Quit

Key Concepts:

-File system architecture

-Memory and block management

-Data structures for storage systems

-Low-level file handling in C

Author:
Gabriel Balogun
Computer Science Student – UTA
