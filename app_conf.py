from multiprocessing import cpu_count

### Listerning
# bind = "127.0.0.1:9999"
bind = 'unix:/opt/pjt/app.sock'

### Worker Options
# Static worker
workers = 6

# CPU depends
workers = cpu_count()

# Worker class == Uvicorn worker
worker_class = 'uvicorn.workers.UvicornWorker'

# Logging Options
loglevel = 'debug'

# Worker timeout
timeout = 600

accesslog = '/opt/pjt/logs/access_log'
errorlog = '/opt/pjt/logs/error_log'
