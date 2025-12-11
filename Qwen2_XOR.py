import asyncio
import json
import base64
import logging
from contextlib import asynccontextmanager
from threading import Thread
from typing import AsyncGenerator
import sys

import torch
import uvicorn
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from transformers import AutoModelForCausalLM, AutoTokenizer, TextIteratorStreamer

# --- 开始：修正后的、基于字节的异或密码实现 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__) # 修正 logger name

def xor_cipher(data_bytes: bytes, key: str) -> bytes:
    """
    对字节数据应用一个简单的重复密钥异或密码。
    此函数现在接收并返回原始字节(bytes)。
    """
    if not key:
        raise ValueError("异或密码需要一个非空的密钥。")
    key_bytes = key.encode('utf-8')
    if not key_bytes:
        raise ValueError("密钥编码后不能为空。")

    encrypted_bytes = bytearray()

    for i in range(len(data_bytes)):
        encrypted_bytes.append(data_bytes[i] ^ key_bytes[i % len(key_bytes)])
        
    return bytes(encrypted_bytes)

def encrypt_payload(data: dict, key: str) -> str:
    """使用异或密码加密JSON负载，并进行Base64编码。"""
    try:
        # 1. 将字典转换为JSON字符串，然后编码为UTF-8字节
        plaintext_bytes = json.dumps(data, ensure_ascii=False).encode('utf-8')
        # 2. 对字节进行异或加密
        encrypted_bytes = xor_cipher(plaintext_bytes, key)
        # 3. 对加密后的原始字节进行Base64编码
        return base64.b64encode(encrypted_bytes).decode('utf-8')
    except Exception as e:
        logger.error(f"加密失败: {e}")
        raise

def decrypt_payload(encrypted_data: str, key: str) -> dict:
    """解密一个经过Base64编码和异或加密的负载。"""
    try:
        # 1. 从Base64解码，得到加密状态的原始字节
        encrypted_bytes = base64.b64decode(encrypted_data)
        # 2. 对字节进行异或解密
        decrypted_bytes = xor_cipher(encrypted_bytes, key)
        # 3. 将解密后的字节（应为JSON格式）解码为字符串
        # 使用错误处理替换无效字符
        decrypted_json = decrypted_bytes.decode('utf-8', errors='replace')
        return json.loads(decrypted_json)
    except Exception as e:
        logger.error(f"解密失败: {e}")
        raise HTTPException(status_code=400, detail="无效的加密负载或密钥。")
# --- 结束：修正后的异或密码实现 ---

# --- API密钥辅助函数 ---
async def get_api_key(request: Request) -> str:
    """用于从请求头中获取和验证API密钥的依赖项。"""
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        raise HTTPException(status_code=401, detail="请求头中需要包含 X-API-Key。")
    return api_key

# 创建FastAPI应用实例
app = FastAPI(
    title="Qwen3 1.7B 简单加密流式API",
    description="一个使用简单、易破解的异或密码的本地Qwen3 1.7B API，支持流式传输。",
    version="3.1-insecure-stream"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
)

# 模型和分词器的全局变量
tokenizer = None
model = None
# 请根据你的实际模型路径修改
MODEL_PATH = r"D:\qwen\Qwen2.5-0.5B-Instruct" # 如有需要，请调整路径

# --- Pydantic模型 ---
class EncryptedRequest(BaseModel):
    payload: str

class GenerateRequest(BaseModel):
    text: str
    max_tokens: int = 512
    temperature: float = 0.1
    top_p: float = 0.9
    repetition_penalty: float = 1.1

class GenerateResponse(BaseModel):
    generated_text: str

# --- 应用生命周期管理 ---
@asynccontextmanager
async def lifespan(app: FastAPI):
    global tokenizer, model
    logger.info("应用启动中...")
    try:
        logger.info(f"正在从以下路径加载模型: {MODEL_PATH}")
        tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
        model = AutoModelForCausalLM.from_pretrained(MODEL_PATH, torch_dtype="auto", device_map="auto")
        logger.info("模型加载成功。")
        yield
    except Exception as e:
        logger.error(f"加载模型失败: {e}")
        raise RuntimeError(f"加载模型失败: {e}")
    finally:
        logger.info("应用关闭，清理资源。")
        model = None
        tokenizer = None
        if torch.cuda.is_available():
            torch.cuda.empty_cache()

app.router.lifespan_context = lifespan

# --- API接口 ---
# 健康检查接口保持不变
@app.get("/health", summary="健康检查", tags=["服务状态"])
async def health_check():
    if model is None or tokenizer is None:
        raise HTTPException(status_code=503, detail="模型未加载。")
    return {"status": "healthy", "model_loaded": True}

@app.post("/secure-health", summary="带认证的健康检查", tags=["服务状态"])
async def secure_health_check(api_key: str = Depends(get_api_key)):
    """测试提供的API密钥是否能解密一条测试消息。"""
    test_payload = {"message": "connection test"}
    try:
        encrypted = encrypt_payload(test_payload, api_key)
        decrypted = decrypt_payload(encrypted, api_key)
        if decrypted == test_payload:
            return {"status": "ok", "detail": "API密钥有效。"}
        else:
            raise HTTPException(status_code=401, detail="解密测试失败。")
    except Exception:
        raise HTTPException(status_code=401, detail="API密钥无效。")

# --- 流式生成接口 ---
@app.post("/stream", summary="流式生成文本（简单加密）", tags=["模型推理"])
async def stream_text(encrypted_request: EncryptedRequest, api_key: str = Depends(get_api_key)):
    """
    流式生成文本。该端点返回一个SSE流，其中每个事件的数据部分
    包含一个用提供的API密钥XOR加密并Base64编码的JSON对象。
    JSON对象格式为 {"token": "generated_token_text"}。
    在流结束时，会发送一个包含完整生成文本的最终包 {"final_full_text": "..."}。
    """
    if model is None or tokenizer is None:
        raise HTTPException(status_code=503, detail="模型未准备好。")

    try:
        # 1. 解密请求
        decrypted_data = decrypt_payload(encrypted_request.payload, api_key)
        request = GenerateRequest(**decrypted_data)

        # 2. 准备输入
        messages = [{"role": "user", "content": request.text}]
        text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        inputs = tokenizer([text], return_tensors="pt").to(model.device)

        # 3. 设置流式处理
        streamer = TextIteratorStreamer(tokenizer, skip_prompt=True, skip_special_tokens=True, timeout=60)

        # 4. 启动生成线程
        generation_kwargs = dict(
            inputs,
            streamer=streamer,
            max_new_tokens=request.max_tokens,
            do_sample=True,
            temperature=request.temperature,
            top_p=request.top_p,
            repetition_penalty=request.repetition_penalty
        )
        thread = Thread(target=model.generate, kwargs=generation_kwargs)
        thread.start()

        # 5. 定义异步生成器来处理流
        async def encrypted_stream_generator() -> AsyncGenerator[str, None]:
            # 用于累积完整响应
            full_response_text = ""
            
            try:
                # 6. 从streamer中迭代获取token
                for new_token in streamer:
                    if new_token: # 确保token不为空
                        # 累积 token
                        full_response_text += new_token
                        
                        # 在控制台实时打印 token
                        sys.stdout.write(new_token)
                        sys.stdout.flush()
                        
                        # 7. 将token放入字典
                        token_data = {"token": new_token}
                        # 8. 加密字典
                        encrypted_chunk = encrypt_payload(token_data, api_key)
                        # 9. 按照SSE格式 yield 数据
                        yield f" {json.dumps({'payload': encrypted_chunk})}\n\n"
                
                # 10. 流结束时在控制台打印换行，方便阅读
                print()
                logger.info("流式传输完成，准备发送最终数据包。")
                
                # 11. 发送包含用户输入和完整响应的数据包
                final_data = {
                    "user_input": request.text,  # 用户原始输入
                    "full_response": full_response_text  # 模型生成的完整文本
                }
                encrypted_final_chunk = encrypt_payload(final_data, api_key)
                yield f" {json.dumps({'payload': encrypted_final_chunk})}\n\n"
                logger.info("最终数据包已发送（包含用户输入和完整响应）。")
            except asyncio.CancelledError:
                logger.info("客户端断开连接，停止流式生成。")
                raise
            except Exception as e:
                logger.error(f"流式传输过程中出错: {e}")
                # 发送错误信息给客户端
                error_data = {"error": "Internal server error during streaming"}
                encrypted_error = encrypt_payload(error_data, api_key)
                yield f" {json.dumps({'payload': encrypted_error})}\n\n"
                return

        # 12. 返回SSE响应
        return StreamingResponse(encrypted_stream_generator(), media_type="text/event-stream")

    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"启动流式文本生成过程中出错: {e}")
        raise HTTPException(status_code=500, detail=str(e))


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5001)