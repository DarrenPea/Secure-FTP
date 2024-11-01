# 50.005 Programming Assignment 2

This assignment requires knowledge from Network Security and basic knowledge in Python.

## Secure FTP != HTTPs

This project implements a **secure** file upload application between a client and a secure file server by fulfilling the following requirements:

1. **Authentication** of the identity of the file server to prevent data leaks to random entity
2. Ensure that the client is talking to a **live** server
3. Ensure **confidentiality** of the data against eavesdroppers

More information on how the above requirements are fulfilled will be dissected [here](https://github.com/DarrenPea/SFTP/tree/master/source)

### Sustainability & Inclusivity improvements
For Sustainability, CPU, memory and bandwidth usage is logged after every transfer to keep track and maintain reasonable and effecient usage of resources.

For Inclusivity, localization is added (Malay/Chinese on top of English) to better suit users from diverse backgrounds.

Note: do make sure the CMD terminal uses an appropriate code page if chinese is the desired language. One such code page is 936:
```
chcp 936
```

## Running the code

### Install required modules

This assignment requires Python >3.10 to run.

You can use `pipenv` to create a new virtual environment and install your modules there. If you don't have it, simply install using pip, (assuming your python is aliased as python3):

```
python3 -m pip install pipenv
```

Then start the virtual environment, upgrade pip, and install the required modules:

```
pipenv shell
python -m ensurepip --upgrade
pip install -r requirements.txt
```

If `ensurepip` is not available, you need to install it, e.g with Ubuntu:

```
# Adjust for your python version
sudo apt-get install python3.10-venv
```

### Run `./cleanup.,sh`

Run this in the root project directory:

```
chmod +x ./cleanup.sh
./cleanup.sh
```

This will create 3 directories: `/recv_files`, `/recv_files_enc`, and `/send_files_enc` in project's root. They are all empty directories that can't be added in `.git`.

### Run server and client files

In two separate shell sessions, run (assuming you're in root project directory):

```
python3 source/ServerWithoutSecurity.py
```

and:

```
python3 source/ClientWithoutSecurity.py
```

### Using different machines

You can also host the Server file in another computer:

```sh
python3 source/ServerWithoutSecurity.py [PORT] 0.0.0.0
```

The client computer can connect to it using the command:

```sh
python3 source/ClientWithoutSecurity.py [PORT] [SERVER-IP-ADDRESS]
```

### Exiting pipenv shell

To exit pipenv shell, simply type:

```
exit
```

Do not forget to spawn the shell again if you'd like to restart the assignment.
