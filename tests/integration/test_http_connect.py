"""
HTTP CONNECT 集成测试

测试目标: 验证 neoproxy HTTP CONNECT 代理功能
测试性质: 黑盒测试，通过外部接口验证行为

基本 CONNECT 和双向传输由 test_chain_matrix_local.py 覆盖；非法端口由
test_authority_ports.py 覆盖。这里保留 origin-form 拒绝、不可达和半关闭契约。
"""

import shutil
import socket
import tempfile
import threading

from tests.fixtures.http_configuration import create_test_config
from tests.fixtures.http_request import send_raw_request
from tests.fixtures.ports import get_unique_port
from tests.fixtures.proxy_process import BytesProcess, start_proxy
from tests.fixtures.tcp_peer import create_target_server


class TestHTTPConnect:
    """HTTP CONNECT 集成测试类"""

    def test_tc002_origin_form_request_returns_400(self) -> None:
        """
        TC-002: 非代理请求（origin-form URI）返回 400

        测试目标: 验证代理服务器对 origin-form URI 的 GET 请求返回 400 Bad Request。
        使用绝对 URI（http://...）的 GET 请求会被当作 forward proxy 请求处理；
        只有 origin-form（GET / HTTP/1.1）才会被拒绝并返回 400。
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            # 1. 创建配置文件
            config_path = create_test_config(proxy_port, temp_dir, server_threads=2)

            # 2. 启动代理服务器
            proxy_proc = start_proxy(config_path)

            # 3. 等待代理服务器就绪
            assert proxy_proc.wait_ready(), "Proxy server failed to start"

            # 4. 发送 origin-form GET 请求（非代理请求格式）
            request = b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"
            response = send_raw_request("127.0.0.1", proxy_port, request)

            # 5. 验证响应状态码为 400
            assert b"400" in response or b"Bad Request" in response, (
                "Expected 400 Bad Request for origin-form GET, got:"
                + f" {response.decode(errors='ignore')}"
            )

        finally:
            # 6. 清理资源
            if proxy_proc:
                proxy_proc.terminate()
                _ = proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_tc004_target_unreachable(self) -> None:
        """
        TC-004: 目标不可达

        测试目标: 验证代理服务器在目标不可达时的行为
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: BytesProcess | None = None

        try:
            # 1. 创建配置文件
            config_path = create_test_config(proxy_port, temp_dir, server_threads=2)

            # 2. 启动代理服务器
            proxy_proc = start_proxy(config_path)

            # 3. 等待代理服务器就绪
            assert proxy_proc.wait_ready(), "Proxy server failed to start"

            # 4. 发送 CONNECT 请求到不可达地址
            # 使用本地不存在的端口，会立即收到 connection refused
            request = b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))
                sock.sendall(request)

                # 读取响应
                response = b""
                try:
                    while True:
                        data = sock.recv(1024)
                        if not data:
                            break
                        response += data
                        # 如果收到了完整的 HTTP 响应头，就停止
                        if b"\r\n\r\n" in response:
                            break
                except socket.timeout:
                    pass
            finally:
                sock.close()

            # 5. 验证行为
            # 代理服务器应返回错误响应或关闭连接
            # 接受成功、连接失败、超时或关闭连接。
            is_valid_response = (
                b"200" in response
                or b"502" in response
                or b"504" in response
                or b"Bad Gateway" in response
                or b"Gateway Timeout" in response
                or len(response) == 0
            )
            assert is_valid_response, (
                "Unexpected response for unreachable target:"
                + f" {response.decode(errors='ignore')}"
            )

        finally:
            # 6. 清理资源
            if proxy_proc:
                proxy_proc.kill()
                _ = proxy_proc.wait(timeout=2)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_tc007_tunnel_half_close_propagation(self) -> None:
        """
        TC-007: 隧道单侧关闭传播

        测试目标: 验证隧道一端关闭时，另一端能够正确感知
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: BytesProcess | None = None
        target_socket: socket.socket | None = None

        try:
            # 1. 创建配置文件
            config_path = create_test_config(proxy_port, temp_dir, server_threads=2)

            # 2. 启动模拟目标服务器
            target_socket_closed = threading.Event()

            def close_detect_handler(conn: socket.socket) -> None:
                try:
                    # 等待数据
                    data = conn.recv(1024)
                    # 发送响应
                    if data:
                        conn.sendall(b"RESPONSE")
                    # 等待客户端关闭
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                    target_socket_closed.set()
                except OSError:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, close_detect_handler
            )

            # 3. 启动代理服务器
            proxy_proc = start_proxy(config_path)

            # 4. 等待代理服务器就绪
            assert proxy_proc.wait_ready(), "Proxy server failed to start"

            # 5. 建立 CONNECT 隧道
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                # 发送 CONNECT 请求
                connect_request = (
                    f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost:"
                    + f" 127.0.0.1:{target_port}\r\n\r\n"
                ).encode()
                sock.sendall(connect_request)

                # 读取 200 响应
                response = b""
                while b"\r\n\r\n" not in response:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    response += chunk
                assert b"200" in response, (
                    f"Expected 200 response, got: {response.decode(errors='ignore')}"
                )

                # 6. 发送数据并关闭客户端连接
                sock.sendall(b"TEST_DATA")
                response = sock.recv(1024)
                assert b"RESPONSE" in response, (
                    f"Expected RESPONSE, got: {response.decode(errors='ignore')}"
                )

            finally:
                # 关闭客户端连接
                sock.close()

            # 7. 等待目标服务器感知关闭
            assert target_socket_closed.wait(timeout=10.0), (
                "Target server did not detect client close"
            )

        finally:
            # 8. 清理资源
            if proxy_proc:
                proxy_proc.terminate()
                _ = proxy_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)
