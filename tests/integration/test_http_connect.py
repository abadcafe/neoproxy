"""
HTTP CONNECT 集成测试

测试目标: 验证 neoproxy HTTP CONNECT 代理功能
测试性质: 黑盒测试，通过外部接口验证行为
"""

import subprocess
import socket
import threading
import tempfile
import shutil
import time
import os
import signal
from typing import Callable, Tuple, List, Dict, Optional

from .utils.helpers import (
    NEOPROXY_BINARY,
    start_proxy,
    wait_for_proxy,
    create_target_server,
    send_raw_request,
    create_test_config,
)
from .conftest import get_unique_port


# ==============================================================================
# 测试辅助函数（本模块特有）
# ==============================================================================


def run_curl_connect(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
    timeout: float = 10.0
) -> Tuple[int, str, str]:
    """
    使用 curl 发送 CONNECT 请求。

    Args:
        proxy_host: 代理服务器地址
        proxy_port: 代理服务器端口
        target_host: 目标主机地址
        target_port: 目标端口
        timeout: curl 超时时间（秒）

    Returns:
        Tuple[int, str, str]:
            - 返回码
            - 标准输出
            - 标准错误
    """
    cmd: List[str] = [
        "curl", "-s", "-p",  # -p 强制使用 CONNECT 方法建立隧道
        "-x", f"http://{proxy_host}:{proxy_port}",
        "--connect-timeout", str(int(timeout)),
        f"http://{target_host}:{target_port}/"
    ]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout + 5
    )
    return result.returncode, result.stdout, result.stderr


# ==============================================================================
# 测试用例
# ==============================================================================


class TestHTTPConnect:
    """HTTP CONNECT 集成测试类"""

    def test_tc001_normal_connect_tunnel(self) -> None:
        """
        TC-001: 正常 CONNECT 隧道建立

        测试目标: 验证 CONNECT 方法能够正常建立 TCP 隧道并双向转发数据
        使用 curl 发送 CONNECT 请求通过代理访问目标服务器
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            # 1. 创建配置文件
            config_path = create_test_config(proxy_port, temp_dir, worker_threads=2)

            # 2. 启动模拟目标服务器
            received_messages: List[bytes] = []

            def http_echo_handler(conn: socket.socket) -> None:
                try:
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        received_messages.append(data)
                        # 返回有效的 HTTP 响应
                        http_response = (
                            b"HTTP/1.1 200 OK\r\n"
                            b"Content-Type: text/plain\r\n"
                            b"Content-Length: 2\r\n"
                            b"\r\n"
                            b"OK"
                        )
                        conn.send(http_response)
                        break  # 发送响应后关闭连接
                except Exception:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, http_echo_handler
            )

            # 3. 启动代理服务器
            proxy_proc = start_proxy(config_path)

            # 4. 等待代理服务器就绪
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            # 5. 使用 curl 发送 CONNECT 请求并验证隧道
            returncode, stdout, stderr = run_curl_connect(
                proxy_host="127.0.0.1",
                proxy_port=proxy_port,
                target_host="127.0.0.1",
                target_port=target_port,
                timeout=10.0
            )

            # 6. 验证 curl 成功执行
            assert returncode == 0, \
                f"curl failed with return code {returncode}, stderr: {stderr}"

            # 7. 验证目标服务器收到数据并返回响应
            assert len(received_messages) > 0, "Target server did not receive any data"

        finally:
            # 8. 清理资源
            if proxy_proc:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_tc002_non_connect_method_returns_405(self) -> None:
        """
        TC-002: 非 CONNECT 方法返回 405

        测试目标: 验证代理服务器对非 CONNECT 方法返回 405 Method Not Allowed
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            # 1. 创建配置文件
            config_path = create_test_config(proxy_port, temp_dir, worker_threads=2)

            # 2. 启动代理服务器
            proxy_proc = start_proxy(config_path)

            # 3. 等待代理服务器就绪
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            # 4. 发送 GET 请求（非 CONNECT 方法）
            cmd: List[str] = [
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "-x", f"http://127.0.0.1:{proxy_port}",
                "http://example.com/"
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10
            )

            # 5. 验证响应状态码
            assert result.stdout.strip() == "405", \
                f"Expected 405, got {result.stdout.strip()}"

        finally:
            # 6. 清理资源
            if proxy_proc:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_tc003_invalid_target_returns_400(self) -> None:
        """
        TC-003: 无效目标地址返回 400

        测试目标: 验证代理服务器对无效目标地址返回 400 Bad Request
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            # 1. 创建配置文件
            config_path = create_test_config(proxy_port, temp_dir, worker_threads=2)

            # 2. 启动代理服务器
            proxy_proc = start_proxy(config_path)

            # 3. 等待代理服务器就绪
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            # 4. 发送缺少端口号的 CONNECT 请求
            request = b"CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n"
            response = send_raw_request("127.0.0.1", proxy_port, request)

            # 5. 验证响应状态码
            assert b"400" in response or b"Bad Request" in response, \
                f"Expected 400 Bad Request, got: {response.decode(errors='ignore')}"

            # 6. 发送端口为 0 的 CONNECT 请求
            request = b"CONNECT example.com:0 HTTP/1.1\r\nHost: example.com\r\n\r\n"
            response = send_raw_request("127.0.0.1", proxy_port, request)

            # 7. 验证响应状态码
            assert b"400" in response or b"Bad Request" in response, \
                f"Expected 400 Bad Request, got: {response.decode(errors='ignore')}"

        finally:
            # 8. 清理资源
            if proxy_proc:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_tc004_target_unreachable(self) -> None:
        """
        TC-004: 目标不可达

        测试目标: 验证代理服务器在目标不可达时的行为
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None

        try:
            # 1. 创建配置文件
            config_path = create_test_config(proxy_port, temp_dir, worker_threads=2)

            # 2. 启动代理服务器
            proxy_proc = start_proxy(config_path)

            # 3. 等待代理服务器就绪
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            # 4. 发送 CONNECT 请求到不可达地址
            # 使用 198.51.100.1 (TEST-NET-2, 用于文档目的, 不可路由)
            request = b"CONNECT 198.51.100.1:9999 HTTP/1.1\r\nHost: 198.51.100.1:9999\r\n\r\n"

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)  # 使用较短超时
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
            # 允许 200（先返回200后连接失败）、502（连接失败）、或空响应
            is_valid_response = (
                b"200" in response or
                b"502" in response or
                b"Bad Gateway" in response or
                len(response) == 0
            )
            assert is_valid_response, \
                f"Unexpected response for unreachable target: {response.decode(errors='ignore')}"

        finally:
            # 6. 清理资源
            if proxy_proc:
                # Use SIGTERM for graceful shutdown and wait longer
                # since tunnel tasks may need time to cleanup
                proxy_proc.send_signal(signal.SIGTERM)
                try:
                    proxy_proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proxy_proc.kill()
                    proxy_proc.wait()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_tc005_concurrent_tunnels(self) -> None:
        """
        TC-005: 并发多个隧道

        测试目标: 验证代理服务器能够同时处理多个 CONNECT 隧道
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            # 1. 创建配置文件
            config_path = create_test_config(proxy_port, temp_dir, worker_threads=2)

            # 2. 启动模拟目标服务器
            connections_count: Dict[str, int] = {"count": 0}
            connections_lock = threading.Lock()

            def counting_handler(conn: socket.socket) -> None:
                with connections_lock:
                    connections_count["count"] += 1
                try:
                    data = conn.recv(1024)
                    if data:
                        # 返回有效的 HTTP 响应
                        http_response = (
                            b"HTTP/1.1 200 OK\r\n"
                            b"Content-Type: text/plain\r\n"
                            b"Content-Length: 2\r\n"
                            b"\r\n"
                            b"OK"
                        )
                        conn.send(http_response)
                except Exception:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, counting_handler
            )

            # 3. 启动代理服务器
            proxy_proc = start_proxy(config_path)

            # 4. 等待代理服务器就绪
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            # 5. 并发发送多个 CONNECT 请求
            num_concurrent = 10  # 满足设计文档 N >= 10 的要求
            results: List[Tuple[int, int, str]] = []
            results_lock = threading.Lock()

            def make_request(request_id: int) -> None:
                try:
                    returncode, stdout, stderr = run_curl_connect(
                        proxy_host="127.0.0.1",
                        proxy_port=proxy_port,
                        target_host="127.0.0.1",
                        target_port=target_port,
                        timeout=15.0
                    )
                    with results_lock:
                        results.append((request_id, returncode, stdout))
                except Exception as e:
                    with results_lock:
                        results.append((request_id, -1, str(e)))

            threads: List[threading.Thread] = []
            for i in range(num_concurrent):
                t = threading.Thread(target=make_request, args=(i,))
                threads.append(t)
                t.start()

            for t in threads:
                t.join(timeout=30)

            # 6. 验证结果
            successful = [r for r in results if r[1] == 0]
            assert len(successful) == num_concurrent, \
                f"Expected {num_concurrent} successful requests, got {len(successful)}: {results}"

        finally:
            # 7. 清理资源
            if proxy_proc:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_tc006_bidirectional_data_transfer(self) -> None:
        """
        TC-006: 隧道双向数据转发

        测试目标: 验证 CONNECT 隧道能够双向转发数据
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            # 1. 创建配置文件
            config_path = create_test_config(proxy_port, temp_dir, worker_threads=2)

            # 2. 启动模拟目标服务器
            received_data: List[bytes] = []

            def echo_handler(conn: socket.socket) -> None:
                try:
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                        received_data.append(data)
                        conn.send(b"ECHO:" + data)
                except Exception:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, echo_handler
            )

            # 3. 启动代理服务器
            proxy_proc = start_proxy(config_path)

            # 4. 等待代理服务器就绪
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            # 5. 建立 CONNECT 隧道并发送数据
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                # 发送 CONNECT 请求
                connect_request = f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n".encode()
                sock.sendall(connect_request)

                # 读取 200 响应
                response = b""
                while b"\r\n\r\n" not in response:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    response += chunk
                assert b"200" in response, \
                    f"Expected 200 response, got: {response.decode(errors='ignore')}"

                # 发送测试数据
                test_data = b"HELLO_WORLD_TEST_DATA"
                sock.sendall(test_data)

                # 接收回显数据
                echo_response = sock.recv(1024)
                assert echo_response == b"ECHO:" + test_data, \
                    f"Expected 'ECHO:{test_data.decode()}', got: {echo_response.decode(errors='ignore')}"

            finally:
                sock.close()

            # 6. 验证目标服务器收到正确数据
            time.sleep(0.5)  # 等待数据传输完成
            assert any(test_data in d for d in received_data), \
                f"Target server did not receive correct data. Received: {received_data}"

        finally:
            # 7. 清理资源
            if proxy_proc:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_tc007_tunnel_half_close_propagation(self) -> None:
        """
        TC-007: 隧道单侧关闭传播

        测试目标: 验证隧道一端关闭时，另一端能够正确感知
        """
        temp_dir = tempfile.mkdtemp()
        proxy_port = get_unique_port()
        target_port = get_unique_port()
        proxy_proc: Optional[subprocess.Popen] = None
        target_socket: Optional[socket.socket] = None

        try:
            # 1. 创建配置文件
            config_path = create_test_config(proxy_port, temp_dir, worker_threads=2)

            # 2. 启动模拟目标服务器
            target_socket_closed = threading.Event()

            def close_detect_handler(conn: socket.socket) -> None:
                try:
                    # 等待数据
                    data = conn.recv(1024)
                    # 发送响应
                    if data:
                        conn.send(b"RESPONSE")
                    # 等待客户端关闭
                    while True:
                        data = conn.recv(1024)
                        if not data:
                            break
                    target_socket_closed.set()
                except Exception:
                    pass
                finally:
                    conn.close()

            _, target_socket = create_target_server(
                "127.0.0.1", target_port, close_detect_handler
            )

            # 3. 启动代理服务器
            proxy_proc = start_proxy(config_path)

            # 4. 等待代理服务器就绪
            assert wait_for_proxy("127.0.0.1", proxy_port, timeout=5.0), \
                "Proxy server failed to start"

            # 5. 建立 CONNECT 隧道
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10.0)
            try:
                sock.connect(("127.0.0.1", proxy_port))

                # 发送 CONNECT 请求
                connect_request = f"CONNECT 127.0.0.1:{target_port} HTTP/1.1\r\nHost: 127.0.0.1:{target_port}\r\n\r\n".encode()
                sock.sendall(connect_request)

                # 读取 200 响应
                response = b""
                while b"\r\n\r\n" not in response:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    response += chunk
                assert b"200" in response, \
                    f"Expected 200 response, got: {response.decode(errors='ignore')}"

                # 6. 发送数据并关闭客户端连接
                sock.sendall(b"TEST_DATA")
                response = sock.recv(1024)
                assert b"RESPONSE" in response, \
                    f"Expected RESPONSE, got: {response.decode(errors='ignore')}"

            finally:
                # 关闭客户端连接
                sock.close()

            # 7. 等待目标服务器感知关闭
            assert target_socket_closed.wait(timeout=10.0), \
                "Target server did not detect client close"

        finally:
            # 8. 清理资源
            if proxy_proc:
                proxy_proc.terminate()
                proxy_proc.wait(timeout=5)
            if target_socket:
                target_socket.close()
            shutil.rmtree(temp_dir, ignore_errors=True)