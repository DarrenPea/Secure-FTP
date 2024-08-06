import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback
from signal import signal, SIGINT
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import os


def chunk_data(data, chunk_size):
    return [data[i:i + chunk_size] for i in range(0, len(data), chunk_size)]


def convert_int_to_bytes(x):
    """
    Convenience function to convert Python integers to a length-8 byte representation
    """
    return x.to_bytes(8, "big")


def convert_bytes_to_int(xbytes):
    """
    Convenience function to convert byte value to integer value
    """
    return int.from_bytes(xbytes, "big")


def read_bytes(socket, length):
    """
    Reads the specified length of bytes from the given socket and returns a bytestring
    """
    buffer = []
    bytes_received = 0
    while bytes_received < length:
        data = socket.recv(min(length - bytes_received, 1024))
        if not data:
            raise Exception("Socket connection broken")
        buffer.append(data)
        bytes_received += len(data)

    return b"".join(buffer)


def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    address = args[1] if len(args) > 1 else "localhost"

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((address, port))
            s.listen()

            client_socket, client_address = s.accept()
            with client_socket:
                while True:
                    match convert_bytes_to_int(read_bytes(client_socket, 8)):
                        case 0:
                            # If the packet is for transferring the filename
                            print("Receiving file...")
                            filename_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            filename = read_bytes(
                                client_socket, filename_len
                            ).decode("utf-8")
                            # print(filename)
                        case 1:
                            # If the packet is for transferring a chunk of the file
                            start_time = time.time()

                            file_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )

                            file_data = read_bytes(client_socket, file_len)
                            # print(file_data)

                            filename = "recv_" + filename.split("/")[-1]
                            with open("source/auth/server_private_key.pem", mode="r", encoding="utf-8") as pem_file:
                                private_key = serialization.load_pem_private_key(
                                    bytes(pem_file.read(), encoding="utf-8"), password=None
                                )
                            key_size = private_key.key_size // 8  # key size in bytes
                            encrypted_chunks = chunk_data(file_data, key_size)

                            decrypted_chunks = []
                            for chunk in encrypted_chunks:
                                # file_data should be encrypted
                                decrypted_chunk = private_key.decrypt(
                                    chunk,
                                    padding.OAEP(
                                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None
                                    )
                                )
                                decrypted_chunks.append(decrypted_chunk)
                            decrypted_data = b''.join(decrypted_chunks)
                            # Write the file with 'recv_' prefix
                            print(decrypted_data)
                            with open(
                                    f"recv_files/{filename}", mode="wb"
                            ) as fp:
                                fp.write(file_data)
                            print(
                                f"Finished receiving file in {(time.time() - start_time)}s!"
                            )
                        case 2:
                            # Close the connection
                            # Python context used here so no need to explicitly close the socket
                            print("Closing connection...")
                            s.close()
                            break
                        case 3:
                            # Authentication
                            try:
                                with open("source/auth/server_private_key.pem", mode="r", encoding="utf-8") as key_file:
                                    private_key = serialization.load_pem_private_key(
                                        bytes(key_file.read(), encoding="utf-8"), password=None
                                    )
                                public_key = private_key.public_key()
                            except Exception as e:
                                print(e)
                                break

                            # Sign message
                            message_len = convert_bytes_to_int(
                                read_bytes(client_socket, 8)
                            )
                            message = read_bytes(
                                client_socket, message_len
                            )
                            signed_message = private_key.sign(
                                message,
                                padding.PSS(
                                    mgf=padding.MGF1(hashes.SHA256()),
                                    salt_length=padding.PSS.MAX_LENGTH
                                ),
                                hashes.SHA256(),
                            )
                            client_socket.sendall(convert_int_to_bytes(len(signed_message)))
                            client_socket.sendall(signed_message)
                            with open("source/auth/server_signed.crt", mode="rb") as cert_file:
                                cert = cert_file.read()
                            client_socket.sendall(convert_int_to_bytes(len(cert)))
                            client_socket.sendall(cert)

    except Exception as e:
        print(e)
        s.close()


def handler(signal_received, frame):
    # Handle any cleanup here
    print('SIGINT or CTRL-C detected. Exiting gracefully')
    exit(0)


if __name__ == "__main__":
    # Tell Python to run the handler() function when SIGINT is recieved
    signal(SIGINT, handler)
    main(sys.argv[1:])
