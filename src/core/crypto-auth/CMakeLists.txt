# Crypto-Auth Component

set(CRYPTO_AUTH_SOURCES
  crypto-auth_public.c
  crypto-auth_priv.c
  crypto-auth_verify.c
)

set(CRYPTO_AUTH_HEADERS
  crypto-auth_public.h
  crypto-auth_priv.h
  crypto-auth_verify.h
)

# Add component
libaura_add_component(
  NAME crypto-auth
  VERSION "1.0.0"
  SOURCES ${CRYPTO_AUTH_SOURCES}
  HEADERS ${CRYPTO_AUTH_HEADERS}
  DEPENDENCIES OpenSSL::SSL OpenSSL::Crypto
)
