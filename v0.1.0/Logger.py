import time
class Logger:
    def __init__(self, log_file):
        self.log_file = log_file

    def log(self, message, classification, save, loud):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        if loud:
            print(f'[{timestamp}] [{classification}] {message}')
        
        if save:
            with open(self.log_file, 'a') as f:
                f.write(f'[{timestamp}] [{classification}] {message}\n')