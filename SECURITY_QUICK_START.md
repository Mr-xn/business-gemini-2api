# 安全修复快速参考 (Security Fixes Quick Reference)

## 使用此修复版本前需要做的事情

### 1. 设置环境变量

创建 `.env` 文件（基于 `.env.example`）：

```bash
cp .env.example .env
```

编辑 `.env` 并设置：

```bash
# 生成强密钥
python3 -c "import secrets; print('ADMIN_SECRET_KEY=' + secrets.token_urlsafe(32))"

# 将输出的密钥添加到 .env 文件中
```

### 2. 生产环境配置

```bash
# .env 文件内容
ADMIN_SECRET_KEY=<你的强随机密钥>
SSL_VERIFY=true
CORS_ORIGINS=https://yourdomain.com
FLASK_ENV=production
ENVIRONMENT=production
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS=100
LOG_LEVEL=INFO
```

### 3. 启动服务

```bash
# 方式1: 直接运行
python3 gemini.py

# 方式2: 使用环境变量
export $(cat .env | xargs) && python3 gemini.py

# 方式3: Docker
docker-compose up -d
```

---

## 主要安全改进

### ✅ 已修复的漏洞

| 漏洞 | 严重性 | 修复 |
|-----|--------|-----|
| 路径遍历 | 高危 | ✅ |
| SSRF | 高危 | ✅ |
| 硬编码密钥 | 中危 | ✅ |
| SSL验证禁用 | 中危 | ✅ |
| CORS配置 | 中危 | ✅ |
| 不安全Cookie | 中危 | ✅ |
| 无速率限制 | 中危 | ✅ |
| 信息泄露 | 低危 | ✅ |
| 缺少安全头 | 低危 | ✅ |

### 📋 新增的环境变量

| 变量名 | 默认值 | 说明 |
|-------|--------|-----|
| `ADMIN_SECRET_KEY` | 自动生成 | 管理后台JWT密钥 |
| `SSL_VERIFY` | false | 是否验证SSL证书 |
| `CORS_ORIGINS` | * | CORS允许的来源 |
| `FLASK_ENV` | - | Flask环境 |
| `ENVIRONMENT` | - | 应用环境 |
| `RATE_LIMIT_ENABLED` | true | 启用速率限制 |
| `RATE_LIMIT_REQUESTS` | 60 | 每分钟请求数 |

---

## 测试安全修复

### 1. 测试路径遍历防护

```bash
# 应该返回 404
curl http://localhost:8000/image/../../../etc/passwd
curl http://localhost:8000/image/..%2F..%2F..%2Fetc%2Fpasswd
```

### 2. 测试SSRF防护

```bash
# 应该返回错误（禁止访问内网）
curl -X POST http://localhost:8000/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "X-API-Token: your-token" \
  -d '{
    "messages": [{
      "role": "user",
      "content": [{
        "type": "image_url",
        "image_url": {
          "url": "http://127.0.0.1/"
        }
      }]
    }]
  }'
```

### 3. 测试速率限制

```bash
# 快速发送多个请求，应该触发 429 错误
for i in {1..100}; do 
  curl http://localhost:8000/health
done
```

### 4. 检查安全响应头

```bash
# 应该看到安全响应头
curl -I http://localhost:8000/
# 期望输出包含:
# X-Content-Type-Options: nosniff
# X-Frame-Options: DENY
# X-XSS-Protection: 1; mode=block
```

---

## 安全检查清单

部署前检查：

- [ ] 已生成并设置强随机的 `ADMIN_SECRET_KEY`
- [ ] 生产环境设置 `SSL_VERIFY=true`
- [ ] 生产环境配置具体的 `CORS_ORIGINS`（不使用 `*`）
- [ ] 设置 `FLASK_ENV=production`
- [ ] 启用速率限制
- [ ] 使用 HTTPS 部署
- [ ] 配置防火墙
- [ ] 设置日志监控
- [ ] 不要将 `.env` 和 `business_gemini_session.json` 提交到版本控制

---

## 如果遇到问题

### 问题1: "ADMIN_SECRET_KEY 未设置"警告

**解决方案**: 
```bash
# 生成密钥并添加到环境变量
export ADMIN_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
```

### 问题2: SSL 验证失败

**解决方案**: 
```bash
# 开发环境可以禁用（不推荐生产环境）
export SSL_VERIFY=false
```

### 问题3: CORS 错误

**解决方案**:
```bash
# 添加你的前端域名
export CORS_ORIGINS=https://yourdomain.com,https://app.yourdomain.com
```

### 问题4: 速率限制过于严格

**解决方案**:
```bash
# 调整限制数量
export RATE_LIMIT_REQUESTS=200
# 或者完全禁用（不推荐）
export RATE_LIMIT_ENABLED=false
```

---

## 升级说明

### 从旧版本升级

如果你正在从旧版本升级，需要：

1. **备份配置文件**
```bash
cp business_gemini_session.json business_gemini_session.json.backup
```

2. **创建 .env 文件**
```bash
cp .env.example .env
# 编辑 .env 并配置环境变量
```

3. **生成新密钥**
```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

4. **重启服务**
```bash
# 停止旧服务
pkill -f gemini.py

# 启动新服务
python3 gemini.py
```

### 兼容性说明

- ✅ API 端点保持不变
- ✅ 配置文件格式兼容
- ✅ 向后兼容（未设置环境变量时使用安全默认值）
- ⚠️ 需要重新登录管理后台（密钥更改）

---

## 获取帮助

- 📖 完整文档: [SECURITY_AUDIT_REPORT.md](./SECURITY_AUDIT_REPORT.md)
- 📝 详细总结: [SECURITY_SUMMARY.md](./SECURITY_SUMMARY.md)
- 🐛 报告问题: GitHub Issues

---

**最后更新**: 2025-12-10
