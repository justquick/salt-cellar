import logging
import click


logger = logging.getLogger('cellar')

LEVEL_MAP = {
    1: logging.WARN,
    2: logging.INFO,
    3: logging.DEBUG
}

class ClickHandler(logging.Handler):
    _use_stderr = True
    colors = {
        'debug': 'white',
        'info': 'yellow',
        'warning': 'bright_yellow',
        'error': 'red',
        'critical': 'bright_red',
    }

    def emit(self, record):
        try:
            msg = self.format(record)
            level = record.levelname.lower()
            click.secho(msg, fg=self.colors[level], err=self._use_stderr)
        except Exception:
            self.handleError(record)

def setup(level=0, filename=None):
    level = LEVEL_MAP.get(level)
    logger.setLevel(level)
    format = '%(asctime)s %(levelname)s %(name)s %(funcName)s: %(message)s'
    # logging.basicConfig(filename=filename, level=level, format=format)
    formatter = logging.Formatter(format)
    console = ClickHandler()
    console.setLevel(level)
    console.setFormatter(formatter)
    logger.addHandler(console)
    if filename:
        filehandler = logging.FileHandler(filename.name)
        filehandler.setLevel(level)
        filehandler.setFormatter(formatter)
        logger.addHandler(filehandler)
