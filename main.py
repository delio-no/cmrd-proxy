import base64
import logging
from twisted.internet import reactor, protocol
from twisted.protocols.policies import TimeoutMixin
from twisted.web import proxy, http

# Настройки логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Пример данных для аутентификации
AUTH_USERS = {
    'user1': 'password1',
    'user2': 'password2',
}

class AuthenticatedProxyRequest(proxy.ProxyRequest):
    def process(self):
        logger.info(f"Received request: {self.method} {self.uri}")

        # Проверка наличия заголовка Authorization
        auth_header = self.getHeader('authorization')
        if not auth_header:
            logger.warning("Authorization header missing")
            self.setHeader('WWW-Authenticate', 'Basic realm="Secure Proxy"')
            self.setResponseCode(http.UNAUTHORIZED)
            self.write(b"Authentication required")
            self.finish()
            return

        # Разбор заголовка Authorization
        auth_type, auth_data = auth_header.split(' ')
        if auth_type.lower() != 'basic':
            logger.warning("Unsupported authentication type")
            self.setResponseCode(http.UNAUTHORIZED)
            self.write(b"Unsupported authentication type")
            self.finish()
            return

        # Декодирование данных аутентификации
        try:
            decoded_data = base64.b64decode(auth_data).decode('utf-8')
            username, password = decoded_data.split(':')
        except Exception as e:
            logger.error(f"Error decoding authentication data: {e}")
            self.setResponseCode(http.UNAUTHORIZED)
            self.write(b"Invalid authentication data")
            self.finish()
            return

        # Проверка аутентификации
        if username not in AUTH_USERS or AUTH_USERS[username] != password:
            logger.warning(f"Invalid username or password for user: {username}")
            self.setResponseCode(http.UNAUTHORIZED)
            self.write(b"Invalid username or password")
            self.finish()
            return

        logger.info(f"Authentication successful for user: {username}")

        # Если аутентификация прошла успешно, продолжаем обработку запроса
        try:
            proxy.ProxyRequest.process(self)
        except Exception as e:
            logger.warning(e)

class AuthenticatedProxy(proxy.Proxy):
    requestFactory = AuthenticatedProxyRequest

class AuthenticatedProxyFactory(http.HTTPFactory):
    protocol = AuthenticatedProxy

if __name__ == "__main__":
    logger.info("Starting proxy server on port 10000")
    reactor.listenTCP(10000, AuthenticatedProxyFactory())
    reactor.run()