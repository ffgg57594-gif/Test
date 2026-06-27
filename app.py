import socket
import threading
import base64
import sys
import select

def decode_auth(auth_header):
    """فك تشفير بيانات المصادقة Basic Auth"""
    if auth_header and auth_header.startswith('Basic '):
        encoded = auth_header[6:]
        decoded = base64.b64decode(encoded).decode('utf-8')
        return decoded.split(':', 1)
    return None, None

def check_auth(client_socket, valid_username, valid_password):
    """التحقق من المصادقة وإرسال طلب المصادقة إذا لزم الأمر"""
    # استقبال البيانات الأولى من العميل
    request = b''
    while b'\r\n\r\n' not in request:
        chunk = client_socket.recv(1)
        if not chunk:
            return False, None
        request += chunk
    
    request_str = request.decode('utf-8', errors='ignore')
    
    # البحث عن رأس المصادقة
    for line in request_str.split('\r\n'):
        if line.lower().startswith('proxy-authorization:'):
            auth_header = line.split(':', 1)[1].strip()
            username, password = decode_auth(auth_header)
            if username == valid_username and password == valid_password:
                return True, request
    
    # إرسال طلب مصادقة
    response = "HTTP/1.1 407 Proxy Authentication Required\r\n"
    response += "Proxy-Authenticate: Basic realm=\"Proxy\"\r\n"
    response += "Content-Length: 0\r\n\r\n"
    client_socket.send(response.encode())
    return False, None

def tunnel_data(source, destination):
    """نقل البيانات بين اتصالين (للـ HTTPS)"""
    try:
        while True:
            rlist, _, _ = select.select([source, destination], [], [])
            if source in rlist:
                data = source.recv(4096)
                if not data:
                    break
                destination.send(data)
            if destination in rlist:
                data = destination.recv(4096)
                if not data:
                    break
                source.send(data)
    except:
        pass
    finally:
        source.close()
        destination.close()

def handle_http_request(client_socket, request_str, target_host, target_port):
    """معالجة طلبات HTTP العادية"""
    try:
        # إعادة كتابة الطلب (إزالة الـ proxy-specific headers)
        lines = request_str.split('\r\n')
        new_lines = []
        for line in lines:
            if not line.lower().startswith('proxy-'):
                new_lines.append(line)
        
        # تعديل سطر الطلب الأول
        if new_lines:
            parts = new_lines[0].split(' ')
            if len(parts) >= 3:
                # استخراج المسار فقط
                url_parts = parts[1].split('/', 3)
                if len(url_parts) >= 4:
                    new_lines[0] = f"{parts[0]} /{url_parts[3]} {parts[2]}"
        
        new_request = '\r\n'.join(new_lines)
        
        # الاتصال بالخادم الهدف
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.connect((target_host, target_port))
        
        # إرسال الطلب المعدل
        target_socket.send(new_request.encode())
        
        # إعادة الاستجابة للعميل
        while True:
            response = target_socket.recv(4096)
            if not response:
                break
            client_socket.send(response)
        
        target_socket.close()
    except Exception as e:
        print(f"HTTP Error: {e}")
    finally:
        client_socket.close()

def handle_client(client_socket, valid_username, valid_password):
    """معالجة اتصال العميل بالكامل (HTTP + HTTPS)"""
    try:
        # التحقق من المصادقة
        auth_result = check_auth(client_socket, valid_username, valid_password)
        if not auth_result[0]:
            return
        
        authenticated_request = auth_result[1]
        if not authenticated_request:
            client_socket.close()
            return
        
        request_str = authenticated_request.decode('utf-8', errors='ignore')
        first_line = request_str.split('\r\n')[0]
        
        # التحقق من نوع الطلب
        if first_line.startswith('CONNECT'):
            # ========== معالجة HTTPS (CONNECT) ==========
            parts = first_line.split(' ')
            if len(parts) >= 2:
                host_port = parts[1].split(':')
                target_host = host_port[0]
                target_port = int(host_port[1]) if len(host_port) > 1 else 443
                
                # الاتصال بالخادم الهدف
                target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target_socket.connect((target_host, target_port))
                
                # إرسال رد نجاح الاتصال للعميل
                client_socket.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                
                # إنشاء نفق ثنائي الاتجاه
                tunnel_data(client_socket, target_socket)
        
        else:
            # ========== معالجة HTTP العادي ==========
            # استخراج الـ host من الطلب
            host_header = None
            for line in request_str.split('\r\n'):
                if line.lower().startswith('host:'):
                    host_header = line.split(':', 1)[1].strip()
                    break
            
            if host_header:
                host_parts = host_header.split(':')
                target_host = host_parts[0]
                target_port = int(host_parts[1]) if len(host_parts) > 1 else 80
                
                handle_http_request(client_socket, request_str, target_host, target_port)
            else:
                client_socket.close()
    
    except Exception as e:
        print(f"Client handling error: {e}")
        try:
            client_socket.close()
        except:
            pass

def start_proxy(host='0.0.0.0', port=8888, username='user', password='pass'):
    """بدء تشغيل خادم البروكسي"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(100)
    
    print(f"✅ Proxy server running on {host}:{port}")
    print(f"🔐 Username: {username}")
    print(f"🔑 Password: {password}")
    print(f"🌐 Supports: HTTP + HTTPS (fully)")
    print("-" * 40)
    
    while True:
        client_socket, addr = server.accept()
        print(f"📡 Connection from {addr[0]}:{addr[1]}")
        client_handler = threading.Thread(
            target=handle_client,
            args=(client_socket, username, password)
        )
        client_handler.daemon = True
        client_handler.start()

if __name__ == "__main__":
    # ======== إعدادات الخادم ========
    PROXY_HOST = '0.0.0.0'      # استمع على جميع الواجهات
    PROXY_PORT = 443         # المنفذ
    PROXY_USER = 'ambtion'    # اسم المستخدم
    PROXY_PASS = '123456' # كلمة المرور
    
    try:
        start_proxy(PROXY_HOST, PROXY_PORT, PROXY_USER, PROXY_PASS)
    except KeyboardInterrupt:
        print("\n🛑 Shutting down proxy server...")
        sys.exit(0)
    except Exception as e:
        print(f"❌ Error: {e}")
        sys.exit(1)
