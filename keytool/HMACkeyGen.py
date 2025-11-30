import os

# 密钥将放在当前脚本所在目录下的 'config' 子目录中
KEY_PATH = "keytool/key/hmac_key.bin"

# 确保 'config' 目录存在
os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True) 

with open(KEY_PATH, "wb") as f:
    f.write(os.urandom(32))

print(f"密钥已写入相对路径: {KEY_PATH}")