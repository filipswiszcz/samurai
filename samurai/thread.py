import threading


class Support_Thread(threading.Thread):

    DIVIDER = "*" * 80

    def __init__(self, *args, **kwargs):
        try:
            self.LOGGER = kwargs.pop("logger")
        except KeyError:
            raise Exception("Missing 'logger' in kwargs.")
        super().__init__(*args, **kwargs)
        self.exception = None

    def run(self):
        try:
            if self._target is not None:
                self._target(*self._args, **self._kwargs)
        except Exception as exc:
            thread = threading.current_thread()
            self.exception = exc
            self.LOGGER.exception(f"{self.DIVIDER}\nException occured in support thread {thread.getName()}: {exc}\n{self.DIVIDER}")
        finally: del self._target, self._args, self._kwargs


class Server_Thread(Support_Thread): pass