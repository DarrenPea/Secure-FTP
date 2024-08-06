import os
import pathlib
import socket
import sys
import time
from datetime import datetime
import secrets
import traceback
import math
import psutil
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as sympadding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Localization dictionaries
localization = {
    "en": {
        "establish_connection": "Establishing connection to server...",
        "connected": "Connected",
        "enter_message": "Enter an arbitrary message:",
        "failed_receive_message": "Failed to receive signed message or certificate from the server.",
        "certificate_verification_failed": "Server certificate verification failed. Closing connection.",
        "signed_message_verification_failed": "Signed message verification failed. Closing connection.",
        "authentication_successful": "Authentication successful",
        "enter_filename": "Enter a filename to send (enter -1 to exit):",
        "invalid_filename": "Invalid filename. Please try again:",
        "closing_connection": "Closing connection...",
        "program_duration": "Program took {}s to run.",
        "usage_statistics": "=== USAGE STATISTICS ===",
        "cpu_usage": "CPU Usage: {}%",
        "memory_usage": "Memory Usage: {}%",
        "bytes_sent": "Bytes Sent: {}",
        "bytes_received": "Bytes Received: {}",
        "language_selected": "You have selected english to interface with this program. Type \"lang\" to change to other languages in the terminal.",
    },
    "ms": {
        "establish_connection": "Menubuhkan sambungan ke pelayan...",
        "connected": "Bersambung",
        "enter_message": "Masukkan mesej sewenang-wenangnya:",
        "failed_receive_message": "Gagal menerima mesej yang ditandatangani atau sijil daripada pelayan.",
        "certificate_verification_failed": "Pengesahan sijil pelayan gagal. Menutup sambungan.",
        "signed_message_verification_failed": "Pengesahan mesej yang ditandatangani gagal. Menutup sambungan.",
        "authentication_successful": "Pengesahan berjaya",
        "enter_filename": "Masukkan nama fail untuk dihantar (masukkan -1 untuk keluar):",
        "invalid_filename": "Nama fail tidak sah. Sila cuba lagi:",
        "closing_connection": "Menutup sambungan...",
        "program_duration": "Program mengambil masa {}s untuk dijalankan.",
        "usage_statistics": "=== STATISTIK PENGGUNAAN ===",
        "cpu_usage": "Penggunaan CPU: {}%",
        "memory_usage": "Penggunaan Memori: {}%",
        "bytes_sent": "Bait Dihantar: {}",
        "bytes_received": "Bait Diterima: {}",
        "language_selected": "Anda telah memilih Bahasa Melayu/Bahasa Indonesia untuk antara muka dengan program ini. Taip \"lang\" untuk menukar kepada bahasa lain dalam terminal.",
    },
    "zh": {
        "establish_connection": "正在建立与服务器的连接...",
        "connected": "已连接",
        "enter_message": "输入任意消息：",
        "failed_receive_message": "未能收到服务器的签名消息或证书。",
        "certificate_verification_failed": "服务器证书验证失败。正在关闭连接。",
        "signed_message_verification_failed": "签名消息验证失败。正在关闭连接。",
        "authentication_successful": "身份验证成功",
        "enter_filename": "输入要发送的文件名（输入-1退出）：",
        "invalid_filename": "文件名无效。请再试一次：",
        "closing_connection": "正在关闭连接...",
        "program_duration": "程序运行了{}秒。",
        "usage_statistics": "=== 使用统计 ===",
        "cpu_usage": "CPU 使用率：{}%",
        "memory_usage": "内存使用率：{}%",
        "bytes_sent": "发送的字节数：{}",
        "bytes_received": "接收的字节数：{}",
        "language_selected": "您已选择已中文与该程序交互。在终端中输入“lang”以更改为其他语言。",
    }
}


def select_language():
    clear = lambda: os.system('cls' if os.name == 'nt' else 'clear')
    clear()
    while True:
        lang = input("Select language (en/ms/zh): ").strip().lower()
        if lang in localization:
            print(localization[lang]["language_selected"])
            return localization[lang]
        else:
            print("Invalid language selection. Please choose 'en' for English, 'ms' for Malay, or 'zh' for Chinese.")
            clear = lambda: os.system('cls' if os.name == 'nt' else 'clear')
            clear()

def log_system_usage(lang):
    # Get CPU usage
    cpu_usage = psutil.cpu_percent(interval=1)

    # Get memory usage
    memory_info = psutil.virtual_memory()
    memory_usage = memory_info.percent

    # Get network usage
    network_info = psutil.net_io_counters()
    bytes_sent = network_info.bytes_sent
    bytes_recv = network_info.bytes_recv

    # Log the system usage
    clear = lambda: os.system('cls' if os.name == 'nt' else 'clear')
    clear()
    print(lang["usage_statistics"])
    print(lang["cpu_usage"].format(cpu_usage))
    print(lang["memory_usage"].format(memory_usage))
    print(lang["bytes_sent"].format(bytes_sent))
    print(lang["bytes_received"].format(bytes_recv))


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


def encrypt_with_symmetric_key(file_data, aes_key, iv):
    # Create a Cipher object using AES in CBC mode
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())

    # Initialize encryptor
    encryptor = cipher.encryptor()

    # Pad file_data and split into chunks
    padder = sympadding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(file_data) + padder.finalize()
    chunk_size = 1024  # Define a chunk size
    chunks = chunk_data(padded_data, chunk_size)

    encrypted_chunks = []
    for chunk in chunks:
        try:
            encrypted_chunk = encryptor.update(chunk)
            encrypted_chunks.append(encrypted_chunk)
        except Exception as e:
            print(f"Encryption failed for a chunk: {e}")
            return None

    # Finalize the encryption and add the final chunk
    encrypted_chunks.append(encryptor.finalize())

    # Combine encrypted chunks into a single bytes object
    encrypted_data = b''.join(encrypted_chunks)

    # Prepend the IV to the encrypted data
    encrypted_data_with_iv = iv + encrypted_data

    return encrypted_data_with_iv


def main(args):
    lang = select_language()

    port = int(args[0]) if len(args) > 0 else 4321
    server_address = args[1] if len(args) > 1 else "localhost"

    start_time = time.time()

    print(lang["establish_connection"])
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((server_address, port))
        print(lang["connected"])

        # Authentication
        nonce = secrets.token_bytes(16)
        authentication_message = input(lang["enter_message"]).strip()
        authentication_message_bytes = nonce + bytes(authentication_message, encoding="utf8")

        # Send the authentication message
        s.sendall(convert_int_to_bytes(3))
        s.sendall(convert_int_to_bytes(len(authentication_message_bytes)))
        s.sendall(authentication_message_bytes)

        signed_message, certificate = receive_message_and_cert(s)

        if not signed_message or not certificate:
            print(lang["failed_receive_message"])
            return

        server_public_key, server_cert = verify_certificate(certificate)

        if not server_public_key or not server_cert:
            print(lang["certificate_verification_failed"])
            s.sendall(convert_int_to_bytes(2))
            return

        if not verify_signed_message(signed_message, authentication_message_bytes, server_public_key):
            print(lang["signed_message_verification_failed"])
            s.sendall(convert_int_to_bytes(2))
            return

        print(lang["authentication_successful"])

        seskey = os.urandom(16)
        iv = os.urandom(16)
        encrypted_key = encrypt_with_public_key(seskey, server_public_key)
        s.sendall(convert_int_to_bytes(4))
        s.sendall(convert_int_to_bytes(len(encrypted_key)))
        s.sendall(encrypted_key)

        while True:
            filename = input(lang["enter_filename"]).strip()

            while filename != "-1" and filename!="lang" and (not pathlib.Path(filename).is_file()):
                filename = input(lang["invalid_filename"]).strip()
            if (filename == "lang"):
                lang=select_language()
                continue
            elif filename == "-1":
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
                encrypted_data_with_iv = encrypt_with_symmetric_key(data, seskey, iv)

                filename = "enc_" + filename.split("/")[-1]
                # Write the file with 'recv_files_enc' prefix
                with open(
                        f"send_files_enc/{filename}", mode="wb"
                ) as fp:
                    fp.write(encrypted_data_with_iv)

                s.sendall(convert_int_to_bytes(1))
                s.sendall(convert_int_to_bytes(len(encrypted_data_with_iv)))
                s.sendall(encrypted_data_with_iv)

            log_system_usage(lang)

        s.sendall(convert_int_to_bytes(2))
        print(lang["closing_connection"])

    end_time = time.time()
    print(lang["program_duration"].format(end_time - start_time))


if __name__ == "__main__":
    main(sys.argv[1:])