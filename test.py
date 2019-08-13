
import logging
from imapper import Client

logger = logging.getLogger(__name__)

def main():
    logging.basicConfig(level=logging.INFO)
    with open('secret', 'r') as f:
        host, username, password, uid = f.read().split()
    logger.info(repr(host))
    with Client(host) as c:
        c.login(username, password)
        c.select()
        c.search('ALL')
        c.fetch(uid, '(RFC822)', uid=True)
        c.logout()

if __name__ == '__main__':
    main()