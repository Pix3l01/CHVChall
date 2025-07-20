import config
import logging

CURRENT_SESSION = config.DEFAULT_SESSION
TIME_ELAPSED = 0

AUTH = False
SEND_ENOA = False
RETRIES = 0
TIME_ENOA_ACTIVATED = 0
BUSY = False

SEED = None

# Create custom logger
logger = logging.getLogger('server')
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.info("Server started. Waiting for packets...")