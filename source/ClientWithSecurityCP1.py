import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback
import math
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

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

def receive_message_and_cert(socket):
    try:
        # Receive signed message
        message_length_bytes = read_bytes(socket, 8)
        message_length = convert_bytes_to_int(message_length_bytes)
        signed_message = read_bytes(socket, message_length)

        # Receive certificate
        cert_length_bytes = read_bytes(socket, 8)
        cert_length = convert_bytes_to_int(cert_length_bytes)
        cert = read_bytes(socket, cert_length)

        return signed_message, cert
    except Exception as e:
        print(f"Error receiving message and certificate: {e}")
        return None, None
    
def verify_certificate(certificate):
    try:
        with open("source/auth/cacsertificate.crt", mode="rb") as f:
            ca_cert_raw = f.read()
        ca_cert = x509.load_pem_x509_certificate(
            data=ca_cert_raw, backend=default_backend()
        )
        ca_public_key = ca_cert.public_key()
        server_cert = x509.load_pem_x509_certificate(
            data=certificate, backend=default_backend()
        )
        ca_public_key.verify(
            signature=server_cert.signature,
            data=server_cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=server_cert.signature_hash_algorithm,
        )
        server_public_key = server_cert.public_key()
        return server_public_key, server_cert
    except InvalidSignature:
        print("Certificate verification failed")
        return None, None

def verify_signed_message(signed_message, original_message, server_public_key):
    try:
        server_public_key.verify(
            signed_message,
            original_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signed message verified")
        return True
    except:
        print("Signed message verification failed")
        return False
def encrypt_with_public_key(file_data, public_key):
    # Calculate the maximum chunk size
    key_size = public_key.key_size // 8
    max_chunk_size = key_size - 2 * hashes.SHA256().digest_size - 2

    # Split the data into chunks
    chunks = chunk_data(file_data, max_chunk_size)

    encrypted_chunks = []
    for chunk in chunks:
        try:
            encrypted_chunk = public_key.encrypt(
                chunk,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            encrypted_chunks.append(encrypted_chunk)
        except Exception as e:
            print(f"Encryption failed for a chunk: {e}")
            return None

    # Combine encrypted chunks into a single bytes object
    encrypted_data = b''.join(encrypted_chunks)
    return encrypted_data
def main(args):
    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()

    # try:
    print("Establishing connection to server...")
    # Connect to server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print("Connected")

        # Authenticatiom
        # Generate nonce to prevent replay attack
        nonce = secrets.token_bytes(16)
        authentication_message = input("Enter an arbitrary message:").strip()
        authentication_message_bytes = nonce + bytes(authentication_message, encoding="utf8")

        # Send the authentication message
        s.sendall(convert_int_to_bytes(3))
        s.sendall(convert_int_to_bytes(len(authentication_message_bytes)))
        s.sendall(authentication_message_bytes)

        signed_message, certificate = receive_message_and_cert(s)
        
        if not signed_message or not certificate:
            print("Failed to receive signed message or certificate from the server.")
            return

        # Verify the certificate
        server_public_key, server_cert = verify_certificate(certificate)

        if not server_public_key or not server_cert:
            print("Server certificate verification failed. Closing connection.")
            s.sendall(convert_int_to_bytes(2))
            return
        
        # Verify the signed message
        if not verify_signed_message(signed_message, authentication_message_bytes, server_public_key):
            print("Signed message verification failed. Closing connection.")
            s.sendall(convert_int_to_bytes(2))
            return
        
        print("Authentication successful")

        while True:
            filename = input(
                "Enter a filename to send (enter -1 to exit):"
            ).strip()

            while filename != "-1" and (not pathlib.Path(filename).is_file()):
                filename = input("Invalid filename. Please try again:").strip()

            if filename == "-1":
                s.sendall(convert_int_to_bytes(2))
                break

            filename_bytes = bytes(filename, encoding="utf8")

            # Send the filename
            s.sendall(convert_int_to_bytes(0))
            s.sendall(convert_int_to_bytes(len(filename_bytes)))
            s.sendall(filename_bytes)

            # Send the file
            with open(filename, mode="rb") as fp:
                data = fp.read()

                encrypted_data = encrypt_with_public_key(data, server_public_key)
                filename = "enc_" + filename.split("/")[-1]
                # Write the file with 'recv_files_enc' prefix
                with open(
                        f"send_files_enc/{filename}", mode="wb"
                ) as fp:
                    fp.write(encrypted_data)
                s.sendall(convert_int_to_bytes(1))
                s.sendall(convert_int_to_bytes(len(encrypted_data)))
                s.sendall(encrypted_data)

        # Close the connection
        s.sendall(convert_int_to_bytes(2))
        print("Closing connection...")

    end_time = time.time()
    print(f"Program took {end_time - start_time}s to run.")


if __name__ == "__main__":
    main(sys.argv[1:])
