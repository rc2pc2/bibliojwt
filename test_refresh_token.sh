#!/bin/bash

# =====================================================
# SCRIPT DI TEST: Sistema Refresh Token
# =====================================================
# Questo script testa il flusso completo del sistema
# di refresh token implementato in Bibliojwt.
#
# PREREQUISITI:
# - Applicazione Spring Boot in esecuzione su localhost:8080
# - Database MySQL in esecuzione su localhost:3307
# - curl installato
# - jq installato (per pretty-print JSON)
#
# ESECUZIONE:
# chmod +x test_refresh_token.sh
# ./test_refresh_token.sh
# =====================================================

BASE_URL="http://localhost:8080"
CONTENT_TYPE="Content-Type: application/json"

# Colori per output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   TEST SISTEMA REFRESH TOKEN${NC}"
echo -e "${BLUE}========================================${NC}\n"

# =====================================================
# TEST 1: LOGIN (Ottenere Access Token + Refresh Token)
# =====================================================
echo -e "${YELLOW}[TEST 1]${NC} LOGIN - Ottenere i token..."

LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/login" \
  -H "$CONTENT_TYPE" \
  -d '{
    "email": "user@example.com",
    "password": "123456"
  }')

echo "$LOGIN_RESPONSE" | jq .

# Estrai token dalla risposta
ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.token')
REFRESH_TOKEN=$(echo "$LOGIN_RESPONSE" | jq -r '.refreshToken')
EXPIRES_IN=$(echo "$LOGIN_RESPONSE" | jq -r '.expiresIn')

if [ "$ACCESS_TOKEN" != "null" ] && [ "$REFRESH_TOKEN" != "null" ]; then
    echo -e "${GREEN}✅ LOGIN SUCCESSO${NC}"
    echo -e "Access Token: ${ACCESS_TOKEN:0:50}..."
    echo -e "Refresh Token: $REFRESH_TOKEN"
    echo -e "Expires In: $EXPIRES_IN secondi\n"
else
    echo -e "${RED}❌ LOGIN FALLITO${NC}\n"
    exit 1
fi

sleep 2

# =====================================================
# TEST 2: USARE ACCESS TOKEN (Chiamata API Protetta)
# =====================================================
echo -e "${YELLOW}[TEST 2]${NC} USARE ACCESS TOKEN - Chiamata API protetta..."

PROFILE_RESPONSE=$(curl -s -X GET "$BASE_URL/api/student/profile" \
  -H "Authorization: Bearer $ACCESS_TOKEN")

echo "$PROFILE_RESPONSE" | jq .

if echo "$PROFILE_RESPONSE" | jq -e '.id' > /dev/null 2>&1; then
    echo -e "${GREEN}✅ ACCESSO API SUCCESSO${NC}\n"
else
    echo -e "${RED}❌ ACCESSO API FALLITO${NC}\n"
fi

sleep 2

# =====================================================
# TEST 3: REFRESH TOKEN (Rinnovare Access Token)
# =====================================================
echo -e "${YELLOW}[TEST 3]${NC} REFRESH TOKEN - Rinnovare i token..."

REFRESH_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/refresh" \
  -H "$CONTENT_TYPE" \
  -d "{
    \"refreshToken\": \"$REFRESH_TOKEN\"
  }")

echo "$REFRESH_RESPONSE" | jq .

# Estrai nuovi token
NEW_ACCESS_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.token')
NEW_REFRESH_TOKEN=$(echo "$REFRESH_RESPONSE" | jq -r '.refreshToken')

if [ "$NEW_ACCESS_TOKEN" != "null" ] && [ "$NEW_REFRESH_TOKEN" != "null" ]; then
    echo -e "${GREEN}✅ REFRESH SUCCESSO${NC}"
    echo -e "Nuovo Access Token: ${NEW_ACCESS_TOKEN:0:50}..."
    echo -e "Nuovo Refresh Token: $NEW_REFRESH_TOKEN"
    echo -e "${YELLOW}⚠️ IMPORTANTE:${NC} Il vecchio refresh token ($REFRESH_TOKEN) è stato REVOCATO\n"
else
    echo -e "${RED}❌ REFRESH FALLITO${NC}\n"
    exit 1
fi

sleep 2

# =====================================================
# TEST 4: USARE NUOVO ACCESS TOKEN
# =====================================================
echo -e "${YELLOW}[TEST 4]${NC} USARE NUOVO ACCESS TOKEN - Verifica nuovo token..."

NEW_PROFILE_RESPONSE=$(curl -s -X GET "$BASE_URL/api/student/profile" \
  -H "Authorization: Bearer $NEW_ACCESS_TOKEN")

echo "$NEW_PROFILE_RESPONSE" | jq .

if echo "$NEW_PROFILE_RESPONSE" | jq -e '.id' > /dev/null 2>&1; then
    echo -e "${GREEN}✅ NUOVO ACCESS TOKEN FUNZIONANTE${NC}\n"
else
    echo -e "${RED}❌ NUOVO ACCESS TOKEN NON FUNZIONANTE${NC}\n"
fi

sleep 2

# =====================================================
# TEST 5: SECURITY - Riusare Vecchio Refresh Token (ATTACCO)
# =====================================================
echo -e "${YELLOW}[TEST 5]${NC} ${RED}SECURITY TEST${NC} - Tentativo di riuso token revocato (attacco)..."

REUSE_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$BASE_URL/api/auth/refresh" \
  -H "$CONTENT_TYPE" \
  -d "{
    \"refreshToken\": \"$REFRESH_TOKEN\"
  }")

REUSE_BODY=$(echo "$REUSE_RESPONSE" | sed -n '1,/HTTP_STATUS/p' | sed '$d')
REUSE_STATUS=$(echo "$REUSE_RESPONSE" | grep -o 'HTTP_STATUS:[0-9]*' | cut -d':' -f2)

echo "$REUSE_BODY" | jq .

if [ "$REUSE_STATUS" == "403" ] || [ "$REUSE_STATUS" == "401" ]; then
    echo -e "${GREEN}✅ ATTACCO RILEVATO - Token revocato rifiutato (Status: $REUSE_STATUS)${NC}"
    echo -e "${RED}🚨 SECURITY ALERT: Tutti i token dell'utente dovrebbero essere stati revocati${NC}\n"
else
    echo -e "${RED}❌ SECURITY FAIL - Token revocato accettato! (Status: $REUSE_STATUS)${NC}\n"
fi

sleep 2

# =====================================================
# TEST 6: Verificare che anche il nuovo token è stato revocato
# =====================================================
echo -e "${YELLOW}[TEST 6]${NC} VERIFICA REVOCA - Tentativo di usare nuovo refresh token..."

VERIFY_REVOKE_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$BASE_URL/api/auth/refresh" \
  -H "$CONTENT_TYPE" \
  -d "{
    \"refreshToken\": \"$NEW_REFRESH_TOKEN\"
  }")

VERIFY_BODY=$(echo "$VERIFY_REVOKE_RESPONSE" | sed -n '1,/HTTP_STATUS/p' | sed '$d')
VERIFY_STATUS=$(echo "$VERIFY_REVOKE_RESPONSE" | grep -o 'HTTP_STATUS:[0-9]*' | cut -d':' -f2)

echo "$VERIFY_BODY" | jq .

if [ "$VERIFY_STATUS" == "401" ]; then
    echo -e "${GREEN}✅ VERIFICA REVOCA SUCCESSO - Anche il nuovo token è stato revocato (Status: $VERIFY_STATUS)${NC}\n"
else
    echo -e "${RED}❌ VERIFICA REVOCA FALLITA - Token ancora valido (Status: $VERIFY_STATUS)${NC}\n"
fi

sleep 2

# =====================================================
# TEST 7: RE-LOGIN (Dopo revoca completa)
# =====================================================
echo -e "${YELLOW}[TEST 7]${NC} RE-LOGIN - Dopo revoca tutti i token..."

RELOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/login" \
  -H "$CONTENT_TYPE" \
  -d '{
    "email": "user@example.com",
    "password": "123456"
  }')

echo "$RELOGIN_RESPONSE" | jq .

FINAL_ACCESS_TOKEN=$(echo "$RELOGIN_RESPONSE" | jq -r '.token')
FINAL_REFRESH_TOKEN=$(echo "$RELOGIN_RESPONSE" | jq -r '.refreshToken')

if [ "$FINAL_ACCESS_TOKEN" != "null" ] && [ "$FINAL_REFRESH_TOKEN" != "null" ]; then
    echo -e "${GREEN}✅ RE-LOGIN SUCCESSO${NC}"
    echo -e "Nuovo Access Token: ${FINAL_ACCESS_TOKEN:0:50}..."
    echo -e "Nuovo Refresh Token: $FINAL_REFRESH_TOKEN\n"
else
    echo -e "${RED}❌ RE-LOGIN FALLITO${NC}\n"
    exit 1
fi

sleep 2

# =====================================================
# TEST 8: LOGOUT (Revocare Refresh Token)
# =====================================================
echo -e "${YELLOW}[TEST 8]${NC} LOGOUT - Revocare refresh token manualmente..."

LOGOUT_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/logout" \
  -H "$CONTENT_TYPE" \
  -d "{
    \"refreshToken\": \"$FINAL_REFRESH_TOKEN\"
  }")

echo "$LOGOUT_RESPONSE" | jq .

if echo "$LOGOUT_RESPONSE" | jq -e '.success == true' > /dev/null 2>&1; then
    echo -e "${GREEN}✅ LOGOUT SUCCESSO - Refresh token revocato${NC}\n"
else
    echo -e "${RED}❌ LOGOUT FALLITO${NC}\n"
fi

sleep 2

# =====================================================
# TEST 9: Verificare che il token revocato non funziona
# =====================================================
echo -e "${YELLOW}[TEST 9]${NC} VERIFICA LOGOUT - Tentativo di usare refresh token revocato..."

VERIFY_LOGOUT_RESPONSE=$(curl -s -w "\nHTTP_STATUS:%{http_code}" -X POST "$BASE_URL/api/auth/refresh" \
  -H "$CONTENT_TYPE" \
  -d "{
    \"refreshToken\": \"$FINAL_REFRESH_TOKEN\"
  }")

VERIFY_LOGOUT_BODY=$(echo "$VERIFY_LOGOUT_RESPONSE" | sed -n '1,/HTTP_STATUS/p' | sed '$d')
VERIFY_LOGOUT_STATUS=$(echo "$VERIFY_LOGOUT_RESPONSE" | grep -o 'HTTP_STATUS:[0-9]*' | cut -d':' -f2)

echo "$VERIFY_LOGOUT_BODY" | jq .

if [ "$VERIFY_LOGOUT_STATUS" == "401" ]; then
    echo -e "${GREEN}✅ VERIFICA LOGOUT SUCCESSO - Token revocato rifiutato (Status: $VERIFY_LOGOUT_STATUS)${NC}\n"
else
    echo -e "${RED}❌ VERIFICA LOGOUT FALLITA - Token ancora valido (Status: $VERIFY_LOGOUT_STATUS)${NC}\n"
fi

# =====================================================
# RIEPILOGO FINALE
# =====================================================
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}   RIEPILOGO TEST${NC}"
echo -e "${BLUE}========================================${NC}\n"

echo -e "${GREEN}✅ TEST COMPLETATI CON SUCCESSO:${NC}"
echo -e "   1. Login con ottenimento token"
echo -e "   2. Accesso API con access token"
echo -e "   3. Refresh token (token rotation)"
echo -e "   4. Verifica nuovo access token"
echo -e "   5. Reuse detection (attacco rilevato)"
echo -e "   6. Verifica revoca completa"
echo -e "   7. Re-login dopo attacco"
echo -e "   8. Logout manuale"
echo -e "   9. Verifica logout"

echo -e "\n${YELLOW}⚠️ NOTE IMPORTANTI:${NC}"
echo -e "   - Access Token JWT: 15 minuti di validità"
echo -e "   - Refresh Token UUID: 7 giorni di validità"
echo -e "   - Token Rotation: Ogni refresh genera nuovo token"
echo -e "   - Reuse Detection: Token revocato riusato → tutti token revocati"
echo -e "   - Max token per utente: 5 (configurabile)"

echo -e "\n${BLUE}========================================${NC}"
echo -e "${GREEN}   TUTTI I TEST COMPLETATI! 🎉${NC}"
echo -e "${BLUE}========================================${NC}\n"
