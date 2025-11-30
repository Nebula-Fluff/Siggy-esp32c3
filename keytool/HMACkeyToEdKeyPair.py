from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import NoEncryption 
import hmac
import hashlib
import binascii

## 配置区 - 请根据你的实际硬件设置修改以下两个变量！
# 1. 你的 HMAC Key (必须是 32 字节的十六进制字符串)
# 设置 HMAC Key 文件的路径
HMAC_KEY_FILE_PATH = 'keytool/key/hmac_key.bin'

try:
    # 尝试读取二进制文件
    with open(HMAC_KEY_FILE_PATH, 'rb') as f:
        hmac_key_bytes = f.read()

    # 检查读取的密钥长度是否为 32 字节
    if len(hmac_key_bytes) != 32:
        raise ValueError(
            f"错误: 密钥文件 '{HMAC_KEY_FILE_PATH}' 的长度必须是 32 字节 (256 bits), "
            f"但实际读取到 {len(hmac_key_bytes)} 字节。"
        )
    
    # 将二进制字节转换为十六进制字符串，供 generate_ed25519_public_key 函数使用
    HMAC_KEY_HEX = hmac_key_bytes.hex()
    print(f"✅ 从文件读取 HMAC Key 成功: {HMAC_KEY_FILE_PATH}")

except FileNotFoundError:
    print(f"❌ 错误: 找不到 HMAC Key 文件: {HMAC_KEY_FILE_PATH}")
    # 在实际应用中，您可能需要在此处退出程序
    HMAC_KEY_HEX = "" # 设置为空，使主函数中的检查失败
except ValueError as e:
    print(e)
    HMAC_KEY_HEX = "" # 设置为空，使主函数中的检查失败
except Exception as e:
    print(f"❌ 读取 HMAC Key 文件时发生未知错误: {e}")
    HMAC_KEY_HEX = ""

# 2. 你的 HMAC Message (种子信息)
# 这对应于你 C 代码中的 seed_sk 的内容，即 'Siggy-1-SEED-NebulaFluff' 的字节表示
SEED_MESSAGE_STRING = 'Siggy-1-SEED-NebulaFluff' 
## --- 配置结束 ---

def generate_ed25519_public_key(hmac_key_hex: str, seed_message_str: str) -> str:
    """
    根据 HMAC 密钥和种子信息计算 Ed25519 密钥对，并返回公钥。
    同时执行签名和验证测试，以确保密钥对功能正常。
    """
    
    # 1. 转换输入数据为字节
    try:
        # HMAC 密钥 (Key)
        hmac_key_bytes = binascii.unhexlify(hmac_key_hex)
        if len(hmac_key_bytes) != 32:
            raise ValueError(f"HMAC Key 长度必须是 32 字节 (256 bits), 当前为 {len(hmac_key_bytes)} 字节.")
        
        # 种子信息 (Message)
        seed_message_bytes = seed_message_str.encode('utf-8')

    except binascii.Error:
        return "错误: HMAC Key 的十六进制字符串格式不正确。"
    except ValueError as e:
        return f"错误: {e}"

    # 2. 计算 HMAC-SHA256 摘要 (作为 Ed25519 私钥种子)
    ed25519_private_seed = hmac.new(
        hmac_key_bytes, 
        seed_message_bytes, 
        hashlib.sha256
    ).digest()

    print(f"✅ 1. HMAC-SHA256 私钥种子（Secret Scalar Seed, 32 字节）:")
    print(f"   {ed25519_private_seed.hex()}")
    
    # 3. 从私钥种子生成 Ed25519 密钥对对象
    try:
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(ed25519_private_seed)
        public_key_obj = private_key.public_key()
        
        # 导出公钥的原始字节 (32 字节)
        public_key_bytes = public_key_obj.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        
        # 导出私钥种子
        private_key_seed_exported = private_key.private_bytes(
            encoding=serialization.Encoding.Raw, 
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=NoEncryption()
        )
        
        # 手动拼接 64 字节密钥对 (种子 + 公钥)
        full_key_pair_hex = (private_key_seed_exported + public_key_bytes).hex()

        print("\n✅ 2. 模拟 Libsodium 风格的 64 字节密钥对（种子 + 公钥）:")
        print(f"   完整密钥对（64字节）: {full_key_pair_hex}")
        print(f"   ┣ 私钥种子（前 32 字节）: {full_key_pair_hex[:64]}")
        print(f"   ┗ 对应公钥（后 32 字节）: {full_key_pair_hex[64:]}")
        
    except ValueError as e:
        return f"错误: 无法从种子生成 Ed25519 密钥对: {e}"

    # --- 签名和验证测试 ---
    TEST_MESSAGE = b"This is a test message for Ed25519 signature."
    
    # 4. 签名测试
    try:
        signature = private_key.sign(TEST_MESSAGE)
        print("\n✅ 3. 签名测试:")
        print(f"   测试消息: {TEST_MESSAGE.decode()}")
        print(f"   签名结果 (64字节): {signature.hex()}")
    except Exception as e:
        print(f"❌ 签名失败: {e}")
        return public_key_bytes.hex() # 即使失败，也返回公钥

    # 5. 验证测试
    try:
        public_key_obj.verify(signature, TEST_MESSAGE)
        print("   签名验证状态: ⭐ 成功通过！密钥对功能正常。")
    except Exception as e:
        print(f"❌ 签名验证失败: {e}")
        # 如果验证失败，说明密钥生成或签名/验证逻辑有问题
        return f"验证失败，请检查 HMAC KEY 和 SEED MESSAGE 是否与硬件一致。错误信息: {e}"

    # 6. 返回公钥的十六进制字符串
    return public_key_bytes.hex()

# 运行主函数并输出结果
final_public_key = generate_ed25519_public_key(HMAC_KEY_HEX, SEED_MESSAGE_STRING)

print("\n--- 🗝️ 最终公钥输出 ---")
if final_public_key.startswith("错误"):
    print(final_public_key)
else:
    print(f"🎉 4. 最终 Ed25519 公钥 (32 字节, 十六进制):")
    print(f"   {final_public_key}")