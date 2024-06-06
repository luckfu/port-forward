import psutil
import uuid
from flask import Flask, render_template_string, request, Response, url_for
from werkzeug.middleware.proxy_fix import ProxyFix
import requests

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)

# 存储编码与端口的映射关系
port_mapping = {}

# 检查端口是否是Web服务
def is_web_service(port):
    try:
        response = requests.get(f'http://localhost:{port}', timeout=1)
        return response.status_code in [200, 301, 302]
    except requests.RequestException:
        return False

# 获取当前用户的进程及其网络端口信息
def get_process_port_info():
    process_port_info = []
    current_pid = psutil.Process().pid
    current_port = request.environ.get('SERVER_PORT')
    
    for proc in psutil.process_iter(attrs=['pid', 'name', 'username']):
        try:
            if proc.info['pid'] == current_pid:
                continue
            connections = proc.connections(kind='inet')
            for conn in connections:
                if conn.laddr and conn.laddr.port:
                    if str(conn.laddr.port) == current_port:
                        continue
                    if is_web_service(conn.laddr.port):
                        # 如果已有该端口的映射，直接使用已有编码
                        if conn.laddr.port in port_mapping:
                            unique_code = port_mapping[conn.laddr.port]
                        else:
                            unique_code = uuid.uuid4().hex
                            port_mapping[conn.laddr.port] = unique_code
                        process_port_info.append({
                            'pid': proc.info['pid'],
                            'name': proc.info['name'],
                            'port': conn.laddr.port,
                            'url': url_for('proxy', code=unique_code, _external=True)
                        })
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    return process_port_info

@app.route('/')
def index():
    process_port_info = get_process_port_info()
    return render_template_string('''
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <title>Process Port Info</title>
            <style>
                table {
                    width: 100%;
                    border-collapse: collapse;
                }
                table, th, td {
                    border: 1px solid black;
                }
                th, td {
                    padding: 8px;
                    text-align: left;
                }
                th {
                    background-color: #4CAF50;
                    color: white;
                }
                tr:nth-child(even) {
                    background-color: #f2f2f2;
                }
            </style>
        </head>
        <body>
            <h1>Process Port Information</h1>
            <table>
                <tr>
                    <th>Process ID</th>
                    <th>Process Name</th>
                    <th>Port</th>
                    <th>URL</th>
                </tr>
                {% for info in process_port_info %}
                <tr>
                    <td>{{ info.pid }}</td>
                    <td>{{ info.name }}</td>
                    <td>{{ info.port }}</td>
                    <td><a href="{{ info.url }}" target="_blank">{{ info.url }}</a></td>
                </tr>
                {% endfor %}
            </table>
        </body>
        </html>
    ''', process_port_info=process_port_info)

@app.route('/<string:code>', defaults={'path': ''})
@app.route('/<string:code>/<path:path>')
def proxy(code, path):
    # 反向查找编码对应的端口
    port = next((port for port, c in port_mapping.items() if c == code), None)
    if not port:
        return "Invalid code", 404

    # 动态构建目标URL，使用请求的主机名和端口
    target_url = f'http://{request.host.split(":")[0]}:{port}/{path}'
    headers = {key: value for key, value in request.headers if key != 'Host'}
    
    try:
        response = requests.request(
            method=request.method,
            url=target_url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False
        )
        
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = [(name, value) for name, value in response.raw.headers.items() if name.lower() not in excluded_headers]
        
        return Response(response.content, response.status_code, headers)
    except requests.exceptions.RequestException as e:
        return f"An error occurred: {e}", 500

if __name__ == '__main__':
    app.run(debug=True)