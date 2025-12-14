from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from transformers import AutoModelForCausalLM, AutoTokenizer, TextIteratorStreamer
import torch
import uvicorn
import logging
import os
from contextlib import asynccontextmanager
from fastapi.responses import StreamingResponse, JSONResponse
import json
import asyncio
from threading import Thread
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 全局变量
private_key = None
tokenizer = None
model = None

# 模型路径
MODEL_PATH = r"D:\qwen\Qwen2.5-0.5B-Instruct"


def decrypt_hybrid_payload(encrypted_request: 'HybridEncryptedRequest') -> tuple[dict, bytes]:
    if not private_key:
        raise HTTPException(status_code=500, detail="Server private key not loaded.")
    try:
        # 1. Decode and decrypt the symmetric key using RSA-OAEP
        encrypted_sym_key = base64.b64decode(encrypted_request.encrypted_key)
        symmetric_key = private_key.decrypt(
            encrypted_sym_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 2. Decrypt the payload with the now-revealed symmetric key (AES-GCM)
        raw_data = base64.b64decode(encrypted_request.payload)
        nonce = raw_data[:12]
        ciphertext = raw_data[12:]
        aesgcm = AESGCM(symmetric_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        return json.loads(plaintext.decode('utf-8')), symmetric_key
    except Exception as e:
        logger.error(f"Hybrid decryption failed: {e}")
        raise HTTPException(status_code=400, detail="Invalid encrypted payload or key.")

def encrypt_symmetric_payload(data: dict, key: bytes) -> str:
    """Encrypts a JSON payload using a provided symmetric key (AES-GCM)."""
    plaintext = json.dumps(data).encode('utf-8')
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # GCM standard nonce size
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return base64.b64encode(nonce + ciphertext).decode('utf-8')
app = FastAPI(
    title="Qwen3 1.7B Secure API (RSA)",
    description="本地部署的 Qwen3 1.7B 模型API服务 (带RSA非对称加密)",
    version="3.0"
)

# 配置CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)
class HybridEncryptedRequest(BaseModel):
    encrypted_key: str  
    payload: str      

class GenerateRequest(BaseModel):
    text: str
    max_tokens: int = 32768
    temperature: float = 0.7
    top_p: float = 0.9
    repetition_penalty: float = 1.1

class GenerateResponse(BaseModel):
    generated_text: str
    model: str = "Qwen3-1.7B"
    tokens_generated: int

# --- END: Modified Request/Response Models ---

# 应用生命周期管理
@asynccontextmanager
async def lifespan(app: FastAPI):
    global tokenizer, model, private_key
    logger.info("应用启动中...")
    try:
        # Load the RSA private key
        try:
            with open(r"D:\XOR\KEY\private_key.pem", "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                )
                print(private_key.public_key)
            logger.info("RSA private key loaded successfully from private_key.pem")
        except Exception as e:
            logger.error(f"模型加载失败: 无法加载RSA私钥 'private_key.pem'. 请确保文件存在. Error: {e}")
            raise RuntimeError(f"Failed to load RSA private key: {e}")

        logger.info(f"开始加载模型: {MODEL_PATH}")
        tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
        model = AutoModelForCausalLM.from_pretrained(
            MODEL_PATH,
            torch_dtype="auto",
            device_map="auto"
        )
        logger.info("模型加载成功")
        yield
    except Exception as e:
        logger.error(f"模型加载失败: {str(e)}")
        raise RuntimeError(f"模型加载失败: {str(e)}")
    finally:
        logger.info("应用关闭，清理资源...")
        model, tokenizer, private_key = None, None, None
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
            logger.info("已释放GPU内存")

app.router.lifespan_context = lifespan

# 健康检查接口
@app.get("/health", summary="健康检查", tags=["服务状态"])
async def health_check():
    if model is None or tokenizer is None or private_key is None:
        raise HTTPException(status_code=503, detail="模型或密钥未加载")
    return {"status": "healthy", "model": MODEL_PATH, "loaded": True}

# --- START: Modified Endpoints for Encryption ---

# 非流式接口
@app.post("/generate", summary="加密文本生成 (RSA)", tags=["模型推理"])
async def generate_text(encrypted_request: HybridEncryptedRequest):
    if model is None or tokenizer is None:
        raise HTTPException(status_code=503, detail="模型未准备好，请稍后再试")

    try:
        decrypted_data, symmetric_key = decrypt_hybrid_payload(encrypted_request)
        request = GenerateRequest(**decrypted_data)
        
        logger.info(f"收到非流式生成请求: {request.text[:50]}...")

        messages = [{"role": "user", "content": request.text}]
        text = tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True, enable_thinking=True
        )
        
        inputs = tokenizer([text], return_tensors="pt").to(model.device)
        streamer = TextIteratorStreamer(tokenizer, skip_prompt=True, skip_special_tokens=True)

        generation_kwargs = dict(
            **inputs, streamer=streamer, max_new_tokens=request.max_tokens,
            do_sample=True, temperature=request.temperature, top_p=request.top_p,
            repetition_penalty=request.repetition_penalty
        )

        thread = Thread(target=model.generate, kwargs=generation_kwargs)
        thread.start()
        full_response = "".join([new_text for new_text in streamer])
        thread.join()

        tokens_generated = len(tokenizer.encode(full_response))
        response_data = GenerateResponse(
            generated_text=full_response, tokens_generated=tokens_generated, model="Qwen3-1.7B"
        )
        encrypted_response = {"payload": encrypt_symmetric_payload(response_data.dict(), symmetric_key)}
        return JSONResponse(content=encrypted_response)

    except torch.cuda.OutOfMemoryError:
        logger.error("GPU内存不足，尝试减少max_tokens值")
        raise HTTPException(status_code=500, detail="GPU内存不足，请尝试减少max_tokens值")
    except Exception as e:
        logger.error(f"生成文本时出错: {str(e)}")
        raise HTTPException(status_code=500, detail=f"文本生成失败: {str(e)}")

# 流式接口
@app.post("/generate-stream", summary="加密流式文本生成 (RSA)", tags=["模型推理"])
async def generate_text_stream(encrypted_request: HybridEncryptedRequest, http_request: Request):
    if model is None or tokenizer is None:
        raise HTTPException(status_code=503, detail="模型未准备好，请稍后再试")

    try:
        decrypted_data, symmetric_key = decrypt_hybrid_payload(encrypted_request)
        request = GenerateRequest(**decrypted_data)

        logger.info(f"收到流式生成请求: {request.text[:50]}...")
        
        messages = [{"role": "user", "content": request.text}]
        text = tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True, enable_thinking=True
        )
        
        inputs = tokenizer([text], return_tensors="pt").to(model.device)
        streamer = TextIteratorStreamer(tokenizer, skip_prompt=True, skip_special_tokens=True)
        
        generation_kwargs = dict(
            **inputs, streamer=streamer, max_new_tokens=request.max_tokens,
            do_sample=True, temperature=request.temperature, top_p=request.top_p,
            repetition_penalty=request.repetition_penalty
        )
        
        thread = Thread(target=model.generate, kwargs=generation_kwargs)
        thread.start()

        async def generate():
            try:
                for new_text in streamer:
                    if await http_request.is_disconnected():
                        logger.warning("客户端已断开连接，终止流式生成")
                        break
                    
                    chunk = {"generated_text": new_text}
                    encrypted_chunk = encrypt_symmetric_payload(chunk, symmetric_key)
                    yield f"data: {json.dumps({'payload': encrypted_chunk})}\n\n"
                
                end_signal = {"is_end": True}
                encrypted_end_signal = encrypt_symmetric_payload(end_signal, symmetric_key)
                yield f"data: {json.dumps({'payload': encrypted_end_signal})}\n\n"
                
                logger.info("流式生成完成")
            
            except asyncio.CancelledError:
                logger.info("流式生成任务被取消（客户端断开）")
            except Exception as e:
                logger.error(f"流式生成过程中出错: {str(e)}")
                error_chunk = {"error": "生成过程中出错"}
                encrypted_error = encrypt_symmetric_payload(error_chunk, symmetric_key)
                yield f"data: {json.dumps({'payload': encrypted_error})}\n\n"

        return StreamingResponse(generate(), media_type="text/event-stream")

    except Exception as e:
        logger.error(f"流式生成文本时出错: {str(e)}")
        raise HTTPException(status_code=500, detail=f"流式文本生成失败: {str(e)}")

# --- END: Modified Endpoints for Encryption ---

# 启动服务
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=5010)

'''@misc{qwen3technicalreport,
      title={Qwen3 Technical Report}, 
      author={Qwen Team},
      year={2025},
      eprint={2505.09388},
      archivePrefix={arXiv},
      primaryClass={cs.CL},
      url={https://arxiv.org/abs/2505.09388}, 
}'''