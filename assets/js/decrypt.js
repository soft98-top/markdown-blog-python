// 密码管理
const PasswordManager = {
    // 密码存储键前缀
    KEY_PREFIX: 'article_password_',
    // 密码过期时间（24小时）
    EXPIRY_TIME: 24 * 60 * 60 * 1000,

    // 获取存储键
    getStorageKey(path) {
        return this.KEY_PREFIX + path;
    },

    // 保存密码
    savePassword(path, password) {
        const data = {
            password: password,
            expires: Date.now() + this.EXPIRY_TIME
        };
        localStorage.setItem(this.getStorageKey(path), JSON.stringify(data));
    },

    // 获取密码
    getPassword(path) {
        const data = localStorage.getItem(this.getStorageKey(path));
        if (!data) return null;

        const parsed = JSON.parse(data);
        if (Date.now() > parsed.expires) {
            localStorage.removeItem(this.getStorageKey(path));
            return null;
        }

        return parsed.password;
    },

    // 清除过期密码
    clearExpiredPasswords() {
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key.startsWith(this.KEY_PREFIX)) {
                const data = JSON.parse(localStorage.getItem(key));
                if (Date.now() > data.expires) {
                    localStorage.removeItem(key);
                }
            }
        }
    }
};

// 获取当前文章路径
function getCurrentPath() {
    return window.location.pathname;
}

// 从URL hash获取密码
function getPasswordFromHash() {
    const hash = window.location.hash;
    if (hash && hash.startsWith('#pwd=')) {
        // 移除hash以保护密码
        const password = hash.substring(5);
        history.replaceState(null, null, window.location.pathname);
        return password;
    }
    return null;
}

// 自动尝试解密
async function tryAutoDecrypt() {
    // 检查是否是加密文章
    const encryptedContent = document.getElementById('encrypted-content');
    if (!encryptedContent) return;

    // 优先从URL hash获取密码
    let password = getPasswordFromHash();
    
    // 如果URL中没有密码，尝试从本地存储获取
    if (!password) {
        password = PasswordManager.getPassword(getCurrentPath());
    }

    if (password) {
        const passwordInput = document.getElementById('article-password');
        passwordInput.value = password;
        await decryptArticle(true); // true表示是自动解密
    }
}

// 添加回车事件监听
document.addEventListener('DOMContentLoaded', function() {
    // 清理过期密码
    PasswordManager.clearExpiredPasswords();

    const passwordInput = document.getElementById('article-password');
    if (passwordInput) {
        passwordInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                decryptArticle();
            }
        });
        
        // 尝试自动解密
        tryAutoDecrypt();
    }
});

async function decryptArticle(isAutoDecrypt = false) {
    const password = document.getElementById('article-password').value;
    const button = document.querySelector('.password-button');
    const originalButtonText = button.innerHTML;

    if (!password) {
        alert('请输入密码！');
        return;
    }

    try {
        // 显示加载状态
        button.innerHTML = '<i class="fa fa-spinner fa-spin"></i> 解密中...';
        button.disabled = true;

        const encryptedContent = document.getElementById('encrypted-content').textContent.trim();
        const encryptedData = base64ToArrayBuffer(encryptedContent);
        
        // 分离IV和加密数据
        const iv = new Uint8Array(encryptedData.slice(0, 12));
        const ciphertext = new Uint8Array(encryptedData.slice(12));
        
        // 使用密码生成密钥
        const encoder = new TextEncoder();
        const passwordBuffer = encoder.encode(password);
        
        // 使用 PBKDF2 导入密钥
        const keyMaterial = await crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            { name: 'PBKDF2' },
            false,
            ['deriveKey']
        );
        
        // 使用与后端相同的参数生成密钥
        const key = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: encoder.encode('fixed_salt_for_blog'),
                iterations: 100000,
                hash: 'SHA-256'
            },
            keyMaterial,
            { name: 'AES-GCM', length: 256 },
            false,
            ['decrypt']
        );

        // 解密数据
        const decrypted = await crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            ciphertext
        );

        // 显示解密后的内容
        const decoder = new TextDecoder();
        const decryptedText = decoder.decode(decrypted);
        
        document.getElementById('decrypted-content').innerHTML = decryptedText;
        document.getElementById('password-form').style.display = 'none';
        document.getElementById('decrypted-content').style.display = 'block';
        
        // 保存正确的密码到本地存储
        PasswordManager.savePassword(getCurrentPath(), password);
        
        // 重新应用代码高亮
        if (typeof hljs !== 'undefined') {
            hljs.highlightAll();
        }
    } catch (error) {
        console.error('解密失败:', error);
        if (!isAutoDecrypt) {
            alert('密码错误或解密失败，请重试！');
        }
        // 恢复按钮状态
        button.innerHTML = originalButtonText;
        button.disabled = false;
    }
}

// Base64 转 ArrayBuffer
function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
} 