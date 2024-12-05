from twisted.internet import reactor, protocol
from twisted.protocols.policies import TimeoutMixin
from twisted.web import proxy, http
from twisted.internet import ssl

# Пример данных для аутентификации
AUTH_USERS = {
    'user1': 'password1',
    'user2': 'password2',
}

class AuthenticatedProxyRequest(proxy.ProxyRequest):
    def process(self):
        # Проверка наличия заголовка Authorization
        auth_header = self.getHeader('authorization')
        if not auth_header:
            self.setHeader('WWW-Authenticate', 'Basic realm="Secure Proxy"')
            self.setResponseCode(http.UNAUTHORIZED)
            self.write(b"Authentication required")
            self.finish()
            return

        # Разбор заголовка Authorization
        auth_type, auth_data = auth_header.split(' ')
        if auth_type.lower() != 'basic':
            self.setResponseCode(http.UNAUTHORIZED)
            self.write(b"Unsupported authentication type")
            self.finish()
            return

        # Декодирование данных аутентификации
        username, password = auth_data.decode('base64').split(':')

        # Проверка аутентификации
        if username not in AUTH_USERS or AUTH_USERS[username] != password:
            self.setResponseCode(http.UNAUTHORIZED)
            self.write(b"Invalid username or password")
            self.finish()
            return

        # Если аутентификация прошла успешно, продолжаем обработку запроса
        proxy.ProxyRequest.process(self)

class AuthenticatedProxy(proxy.Proxy):
    requestFactory = AuthenticatedProxyRequest

class AuthenticatedProxyFactory(http.HTTPFactory):
    protocol = AuthenticatedProxy

if __name__ == "__main__":
    reactor.listenTCP(8080, AuthenticatedProxyFactory())
    reactor.run()