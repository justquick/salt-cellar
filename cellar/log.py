import logging


logger = logging.getLogger('cellar')
format = '%(asctime)s %(levelname)s %(name)s %(funcName)s: %(message)s'
logging.basicConfig(filename='cellar.log', level=logging.DEBUG, format=format)
console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
formatter = logging.Formatter(format)
console.setFormatter(formatter)
logger.addHandler(console)
