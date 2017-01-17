# File-server
This is one project from Lehigh CSE303 course which enables user to upload and download file in multiple secure methods.

## Features:
1. a server listening on certain port so that client can connect it to send and recieve files.
2. a well-defined protocol for client and server so that they can send file fast and correctly.
3. Using md5 to verify, public-private key to encrypt the content of file.
4. Implemented LRU cache on both client and server. 

# How to run?

##Preparation:
1. Clone the repository.
2. `cd` to the newly cloned project.
3. Run `make` in command line to get output file in `./obj64`.


## About server:
1. To run server, you need to build one folder as root of server. 
2. `cd` to that folder and execute server file with `./.../server`. Here, `server` is the file in `./obj64` folder.
3. There are three parameters: `-h` help; `-l` cache basket #; `-p` port.

## About client:
1. To run client, you also need to build one folder as root of client.
2. `cd` to that folder and execute server file with `./.../client`. Here, `client` is the file in `./obj64` folder.
3. There are six parameters: `-h` help; `-s` server IP; `-P` put file name; `-G` get file name; `-S` save file name; `-P port.
4. You can build pem encryption file with:

    ```
    openssl genrsa -out private.pem 2048
    openssl rsa -in private.pem -outform PEM -pubout -out public.pem
    ```

and put them in ./obj64. Program would recognize them and encrypt or decrypt file automatically.

## Technology stack
RSA, Openssl, md5, Socket