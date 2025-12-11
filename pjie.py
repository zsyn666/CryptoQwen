import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import time
from tqdm import tqdm
from difflib import SequenceMatcher  # Python内置的字符串相似度工具
import os
def calculate_similarity(text1, text2):
    return SequenceMatcher(None, text1, text2).ratio()
def load_reference_text(filename="main.txt"):
    if not os.path.exists(filename):
        print(f"\033[91m警告：未找到参考文件 {filename}，跳过相似度检测。\033[0m")
        return ""
    try:
        with open(filename, "r", encoding="utf-8") as f:
            return f.read().strip()
    except Exception as e:
        print(f"\033[91m加载参考文件失败: {e}\033[0m")
        return ""
def decode_possible_unicode_escape(data):
    """尝试解码可能的Unicode转义序列"""
    try:
        if b'\\u' in data:
            decoded = data.decode('unicode_escape')
            return decoded.replace("\\n", "\n")
    except Exception:
        pass
    
    try:
        return data.decode('utf-8').replace("\\n", "\n")
    except UnicodeDecodeError:
        for encoding in ['gbk', 'gb2312', 'latin1']:
            try:
                return data.decode(encoding).replace("\\n", "\n")
            except:
                continue
    
    return data.hex()

def xor_cipher_bytes(data_bytes: bytes, key: str) -> bytes:
    if not key:
        print("错误：密钥不能为空。")
        return None
    
    try:
        key_bytes = key.encode('utf-8')
        key_len = len(key_bytes)
        result_bytes = bytearray(len(data_bytes))
        
        for i in range(len(data_bytes)):
            result_bytes[i] = data_bytes[i] ^ key_bytes[i % key_len]
        return bytes(result_bytes)
    except Exception as e:
        print(f"异或操作时发生错误: {e}")
        return None

def aes_decrypt(data_bytes: bytes, key: str) -> bytes:
    try:
        key_bytes = key.encode('utf-8')
        key_bytes = key_bytes.ljust(32, b'\0')[:32]
        
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        decrypted = cipher.decrypt(data_bytes)
        return unpad(decrypted, AES.block_size)
    except Exception as e:
        print(f"AES解密失败: {e}")
        return None

def double_base64_decrypt(data_bytes: bytes) -> bytes:
    try:
        decoded_str = data_bytes.decode('utf-8')
        return base64.b64decode(decoded_str)
    except:
        return None

def main():
    print("==============================")
    print("  多算法解密工具")
    print("==============================")
    
    try:
        ciphertext_b64 = input("\n请输入待解密密文: ").strip()
        key = "123"

        if not ciphertext_b64:
            print("\n\033[91m错误：密文不能为空。\033[0m")
            return
        encrypted_bytes = base64.b64decode(ciphertext_b64)

        results = []
        
        # AES解密
        print(f"\n尝试 AES-ECB 解密...")
        with tqdm(total=100, desc="AES解密进度", ncols=70, leave=True,position=0) as pbar:
            for i in range(10):
                time.sleep(0.5)
                pbar.update(10)
        aes_result = aes_decrypt(encrypted_bytes, key)
        if aes_result:
            try:
                plaintext = decode_possible_unicode_escape(aes_result)
                results.append(("AES", plaintext))
                print("✅ AES解密成功")
            except Exception as e:
                print(f"❌❌ AES解密结果处理失败:")
        else:
            print(f"❌❌ AES解密失败")
        
        # 双重Base64解密
        print(f"\n尝试双重Base64解密...")
        with tqdm(total=100, desc="双重Base64进度", ncols=70, leave=True,position=0) as pbar:
            for i in range(10):
                time.sleep(0.5)
                pbar.update(10)
        base64_result = double_base64_decrypt(encrypted_bytes)
        if base64_result:
            try:
                plaintext = decode_possible_unicode_escape(base64_result)
                results.append(("Double Base64", plaintext))
                print("✅ 双重Base64解密成功")
            except Exception as e:
                print(f"❌❌ 双重Base64结果处理失败: {e}")
        else:
            print(f"❌❌ 双重Base64解密失败")
        
        # XOR解密
        print(f"\n尝试 XOR 解密...")
        with tqdm(total=100, desc="XOR解密进度", ncols=70, leave=True,position=0) as pbar:
            for i in range(10):
                time.sleep(0.1)
                pbar.update(10)
        xor_result = xor_cipher_bytes(encrypted_bytes, key)
        if xor_result:
            try:
                plaintext = decode_possible_unicode_escape(xor_result)
                results.append(("XOR", plaintext))
                print("✅ XOR解密成功")
            except Exception as e:
                print(f"❌❌ XOR解密结果处理失败: {e}")
        else:
            print(f"❌❌ XOR解密失败")
        
        # 显示结果
        if not results:
            print("\n\033[91m所有解密算法均失败！\033[0m")
            return
            
        print("\n------------------------------")
        print("\033[92m解密结果:\033[0m")
        print("------------------------------")

        # 新增：加载 main.txt 内容
        reference_text = load_reference_text()

        for i, (algo, plaintext) in enumerate(results):
            print(f"\n\033[94m算法 {i+1}: {algo}\033[0m")
            print("------------------------------")
            
            # 尝试格式化为JSON
            if isinstance(plaintext, str):
                try:
                    parsed_json = json.loads(plaintext)
                    formatted_text = json.dumps(parsed_json, indent=4, ensure_ascii=False)
                    print(formatted_text)
                except json.JSONDecodeError:
                    print(plaintext)
                    formatted_text = plaintext
            else:
                print(plaintext)
                formatted_text = str(plaintext)

            if reference_text:
                similarity = calculate_similarity(reference_text,formatted_text)
                print("相似度,",similarity)
                if  similarity > 0.4:
                    print("高相似度，此处存在数据泄露")
                else:
                    print("低相似度，数据安全")

    except (base64.binascii.Error, ValueError) as e:
        print(f"\033[91mBase64解码错误: {e}\033[0m")
    except Exception as e:
        print(f"\033[91m发生未预期错误: {e}\033[0m")

if __name__ == "__main__":
    main()