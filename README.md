# Qwen3 加密通信系统

一个基于Qwen3 1.7B模型的多加密方案API服务，支持RSA非对称加密、XOR对称加密和AES解密。

## 项目概述

本项目提供了三个核心模块，实现了不同加密方案的文本生成和解密功能：

- **RSA加密方案**：使用RSA-OAEP非对称加密 + AES-GCM对称加密的混合加密
- **XOR加密方案**：使用简单XOR密码的轻量级加密
- **多算法解密工具**：支持AES、Base64、XOR等多种解密算法

## 文件说明

### 核心模块
- **`pjie.py`** - 多算法解密工具
  - 支持AES-ECB、双重Base64、XOR三种解密方式
  - 自动尝试多种编码格式（UTF-8、GBK、GB2312等）
  - 支持JSON格式化输出
  - 包含相似度检测功能，用于数据泄露识别

- **`Qwen2_RSA.py`** - RSA混合加密API服务
  - FastAPI框架实现
  - 使用RSA-OAEP加密对称密钥
  - 使用AES-GCM加密实际数据
  - 支持流式和非流式文本生成
  - 端口：5010

- **`Qwen2_XOR.py`** - XOR加密API服务
  - FastAPI框架实现
  - 使用简单XOR密码加密
  - 支持流式文本生成（SSE格式）
  - API密钥认证机制
  - 端口：5001

### 配置和密钥
- **`qwen3.yaml`** - Conda环境配置文件
  - 包含所有依赖包版本信息
  - CUDA 11.7支持
  - PyTorch、Transformers等深度学习框架

- **`KEY/`** - 密钥文件夹
  - `private_key.pem` - RSA私钥（用于服务端解密）
  - `public.pem` - RSA公钥（用于客户端加密）

### 测试和参考
- **`main.txt`** - 参考文本（用于相似度检测）
  - 包含示例财务报表数据
  - 用于识别数据泄露

- **`test.txt`** - 测试数据
  - 加密的测试消息

## 环境要求

- Python 3.10+
- CUDA 11.7（GPU加速）
- 依赖包：见 `qwen3.yaml`

主要依赖：
```
torch==2.9.1
transformers==4.37.0
fastapi==0.104.1
uvicorn==0.24.0
cryptography==46.0.3
pycryptodome==3.23.0
```

## 安装

1. 使用Conda创建环境：
```bash
conda env create -f qwen3.yaml
conda activate qwen3
```

2. 下载Qwen2.5-0.5B-Instruct模型：
```bash
# 修改代码中的MODEL_PATH为实际模型路径
# 默认路径：D:\qwen\Qwen2.5-0.5B-Instruct
```

## 使用方法

### 1. 解密工具
```bash
python pjie.py
# 输入Base64编码的密文，工具会自动尝试多种解密方式
```

### 2. RSA加密API服务
```bash
python Qwen2_RSA.py
# 服务启动在 http://localhost:5010
# 需要RSA公钥进行客户端加密
```

### 3. XOR加密API服务
```bash
python Qwen2_XOR.py
# 服务启动在 http://localhost:5001
# 使用API密钥进行认证
```

## API接口

### RSA服务 (端口 5010)

**健康检查**
```
GET /health
```

**文本生成（非流式）**
```
POST /generate
Content-Type: application/json

{
  "encrypted_key": "base64编码的RSA加密对称密钥",
  "payload": "base64编码的AES-GCM加密请求"
}
```

**文本生成（流式）**
```
POST /generate-stream
Content-Type: application/json

{
  "encrypted_key": "base64编码的RSA加密对称密钥",
  "payload": "base64编码的AES-GCM加密请求"
}
```

### XOR服务 (端口 5001)

**健康检查**
```
GET /health
```

**带认证的健康检查**
```
POST /secure-health
Headers: X-API-Key: your-api-key
```

**流式文本生成**
```
POST /stream
Headers: X-API-Key: your-api-key
Content-Type: application/json

{
  "payload": "base64编码的XOR加密请求"
}
```

## 加密流程

### RSA混合加密流程
1. 客户端生成随机对称密钥（AES-256）
2. 使用RSA公钥加密对称密钥
3. 使用AES-GCM加密请求数据
4. 服务端使用RSA私钥解密对称密钥
5. 使用对称密钥解密请求数据

### XOR加密流程
1. 客户端使用API密钥进行XOR加密
2. 对加密数据进行Base64编码
3. 服务端使用API密钥进行XOR解密
4. 返回加密的响应数据

## 功能特性

- ✅ 多种加密方案支持
- ✅ 流式文本生成
- ✅ 自动编码检测
- ✅ JSON格式化输出
- ✅ 数据泄露检测
- ✅ CORS跨域支持
- ✅ 详细日志记录
- ✅ GPU加速推理

## 已知问题

### 🐛 XOR加密流式传输实现问题（奇怪了，暑假的时候还是好的）
**位置**：`Qwen2_XOR.py` - `/stream` 端点

**问题描述**：
- SSE流式传输中，加密数据格式不正确
- 每个事件数据前多余的空格导致客户端解析失败
- 流结束信号处理不完善

**影响范围**：
- 流式文本生成功能无法正常工作
- 客户端无法正确接收和解密流式数据

**临时方案**：
- 使用非流式接口
- 或等待修复后的版本（没有机会了）

**修复计划**：
- [ ] 修正SSE数据格式
- [ ] 改进流结束信号处理
- [ ] 添加客户端测试用例

## 注意事项

- RSA方案提供更强的安全性，适合生产环境
- XOR方案仅用于演示，不建议用于生产环境
- 确保密钥文件安全存储
- 模型路径需要根据实际环境修改

## 许可证

MIT
