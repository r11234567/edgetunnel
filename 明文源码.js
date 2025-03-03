// worker.js
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const clientIP = request.headers.get('CF-Connecting-IP');

    // 管理员生成UUID接口
    if (url.pathname === '/admin/generate') {
      return handleAdminGenerate(request, env, clientIP);
    }

    // 用户验证接口
    if (url.pathname === '/verify') {
      return handleUserVerify(request, env, clientIP);
    }

    return new Response('Not Found', { status: 404 });
  }
}

// 管理员生成UUID
async function handleAdminGenerate(request, env, clientIP) {
  // 验证管理员权限
  if (!validateAdminRequest(request, env)) {
    return new Response('Unauthorized', { status: 401 });
  }

  // 生成UUID
  const uuid = crypto.randomUUID();
  
  // 存储到KV（包含客户端IP）
  await env.AUTH_UUID_STORE.put(uuid, JSON.stringify({
    valid: true,
    clientIP: clientIP,
    created: Date.now()
  }), { expirationTtl: 3600 }); // 1小时有效期

  return jsonResponse({ uuid });
}

// 用户验证
async function handleUserVerify(request, env, clientIP) {
  const { uuid, token } = await request.json();
  
  // 并行验证
  const [uuidData, tsValid] = await Promise.all([
    env.AUTH_UUID_STORE.get(uuid).then(v => v ? JSON.parse(v) : null),
    verifyTurnstile(token, env.TURNSTILE_SECRET)
  ]);

  // 验证逻辑
  const errors = [];
  if (!uuidData || !uuidData.valid) errors.push('无效验证码');
  if (uuidData?.clientIP !== clientIP) errors.push('IP地址不匹配');
  if (!tsValid) errors.push('人机验证失败');

  // 清理已用UUID
  if (uuidData) await env.AUTH_UUID_STORE.delete(uuid);

  return jsonResponse({
    valid: errors.length === 0,
    errors
  });
}

// Turnstile验证
async function verifyTurnstile(token, secret) {
  const form = new FormData();
  form.append('secret', secret);
  form.append('response', token);
  
  const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body: form
  });
  
  return (await res.json()).success;
}

// 管理员请求验证
function validateAdminRequest(request, env) {
  return request.headers.get('X-Admin-Key') === env.ADMIN_KEY &&
         env.ADMIN_IPS.includes(request.headers.get('CF-Connecting-IP'));
}

// 工具函数
function jsonResponse(data) {
  return new Response(JSON.stringify(data), {
    headers: { 
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': env.ALLOWED_ORIGIN
    }
  });
}
