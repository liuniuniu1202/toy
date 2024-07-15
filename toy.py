import base64
import random
import hashlib

def generate_key(seed, length):
    random.seed(seed)
    return [random.randint(0, 255) for _ in range(length)]

def xor_encrypt(text, key):
    return bytes([b ^ k for b, k in zip(text, key)])

def shuffle_encrypt(text, seed):
    random.seed(seed)
    indexes = list(range(len(text)))
    random.shuffle(indexes)
    shuffled = ''.join(text[i] for i in indexes)
    return shuffled, indexes

def shuffle_decrypt(text, indexes):
    result = [''] * len(text)
    for i, index in enumerate(indexes):
        result[index] = text[i]
    return ''.join(result)

def complex_encrypt(text, seed):
    # Convert text to bytes
    text_bytes = text.encode()

    # Generate key for XOR encryption
    key = generate_key(seed, len(text_bytes))
    xor_encrypted = xor_encrypt(text_bytes, key)

    # Base64 encode the XOR encrypted text
    base64_encrypted = base64.urlsafe_b64encode(xor_encrypted).decode()

    # Shuffle the Base64 encoded string
    shuffled, indexes = shuffle_encrypt(base64_encrypted, seed)

    # Obfuscate by adding random characters
    final_encrypted = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') + char for char in shuffled)
    
    return final_encrypted, indexes

def complex_decrypt(encrypted_text, seed, indexes):
    # Remove the random characters
    base64_shuffled = encrypted_text[1::2]

    # Deshuffle the Base64 encoded string
    deshuffled = shuffle_decrypt(base64_shuffled, indexes)

    # Base64 decode
    xor_encrypted = base64.urlsafe_b64decode(deshuffled)

    # Generate key for XOR decryption
    key = generate_key(seed, len(xor_encrypted))
    decrypted_bytes = xor_encrypt(xor_encrypted, key)

    # Convert bytes to string
    decrypted_text = decrypted_bytes.decode()
    
    return decrypted_text

# Example usage:
message = "Hello, World!"
seed = 12345

encrypted_message, indexes = complex_encrypt(message, seed)
print("Encrypted:", encrypted_message)

decrypted_message = complex_decrypt(encrypted_message, seed, indexes)
print("Decrypted:", decrypted_message)
