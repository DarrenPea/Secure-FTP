## Non-Secure FTP
Without any implementation, *ClientWithoutSecurity.py* and *ServerWithoutSecurity.py* is a simple, **non-secure** file transfer protocol (FTP).

Upon a successful connection between client and server, the client will send a `MODE` value, then send streams of message depending on the purpose of each `MODE`.

The first message, `M1`, will be the size of the second message and the second message, `M2`, will be the actual content of the message. This allows the server to read the number of bytes set in M1 from the socket.<br>
Meanwhile, the server will listen to the `MODE` sent by the client, and attempt to read from the socket accordingly.

There are 3 `MODE` values implemented for us.
| `MODE` | message received by the server |
| ------ | ------- |
| `0` | `M1`: filename length<br> `M2`: filename data itself |
| `1` | `M1`: size for data block in bytes<br> `M2`: data block itself |
| `2` | connection close request (no message expected) |

As part of the project, there will be 2 protocols implemented to ensure all 3 requirements are fulfilled, the Authentication Protocol and the Confidentiality Protocol.

## Authentication Protocol
We implemented a new `MODE 3`, for an authentication handshake with *ClientWithSecurityAP.py* and *ServerWithSecurityAP.py*.

For this new mode, the server will expect `M1`, the authetication message size, and `M2`, the authentication message itself.<br>
Then, the client will first read `M1`, the size of incoming `M2`, and `M2`, a signed authentication message. After that, the client will read `M1`, the size of another incoming message `M2`, and `M2`, a server_signed.crt.

Once all 4 messages are received by the client, it will verify the signed certificate using a Certificate Authority's (CA) public key and extract the server's public key from it. Then, the signed message is decrypted using the server's public key to verify that the signed and original message are the same. If the event where any of these steps fail, the connection will be closed immediately.

However, malicious parties can still eavesdrop on the file transfer process, potentially leaking our personal information.

## Confidentiality Protocol
We implemented 2 different ways to ensure confidentiality:<br>
1. *ClientWithSecurityCP1.py* and *ServerWithSecurityCP1.py*: uses **public** key cryptography
2. *ClientWithSecurityCP2.py* and *ServerWithSecurityCP2.py*: uses **symmetric** key cryptography

### Public key cryptography
From the Authentication Protocol, we have already obtained the server's public key. With the server's public key, we can encrypt the data so that the server will be able to decrypt it with its private key.

### Symmetric key cryptography
We implemented a new `MODE 4`, for a key generation handshake.

After the authentication protocol, the client generates a session key and sends the encrypted session key to the server using the server's public key. Then, the file transfer process will proceed using symmetric key encryption. <br>
For the server, it will receive and decrypt the encrypted session key using its private key, and the decrypted session key will be used to decrypt the encrypted files in the file transfer process.