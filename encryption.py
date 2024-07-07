# -*- coding: gbk -*-
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

# 生成 Diffie-Hellman 密钥对
def generate_dh_key_pair():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    return private_key, public_key

# 计算共享密钥
def compute_shared_key(private_key, peer_public_key):
    peer_public_key = serialization.load_pem_public_key(peer_public_key.encode('utf-8'), backend=default_backend())
    shared_key = private_key.exchange(peer_public_key)
    return shared_key