# gunicorn.conf.py
import multiprocessing

# 绑定的IP和端口
bind = "0.0.0.0:80"

# 工作进程数
workers = multiprocessing.cpu_count() * 2 + 1

# 工作模式
worker_class = "sync"

# 最大客户端并发数量
worker_connections = 1000

# 进程文件
pidfile = "gunicorn.pid"

# 访问日志和错误日志
accesslog = "access.log"
errorlog = "error.log"

# 日志级别
loglevel = "info"

# 后台运行
daemon = True

# 启动用户
# user = "your_username"

# 启动用户组
# group = "your_group"

# 超时时间
timeout = 30

# 优雅的重启时间
graceful_timeout = 30

# 重启间隔
reload = True