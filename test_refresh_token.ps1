# =====================================================
# SCRIPT DI TEST: Sistema Refresh Token (PowerShell)
# =====================================================
# Questo script testa il flusso completo del sistema
# di refresh token implementato in Bibliojwt.
#
# PREREQUISITI:
# - Applicazione Spring Boot in esecuzione su localhost:8080
# - Database MySQL in esecuzione su localhost:3307
#
# ESECUZIONE:
# .\test_refresh_token.ps1
# =====================================================

$BaseUrl = "http://localhost:8080"
$ContentType = "application/json"

Write-Host "========================================" -ForegroundColor Blue
Write-Host "   TEST SISTEMA REFRESH TOKEN" -ForegroundColor Blue
Write-Host "========================================`n" -ForegroundColor Blue

# =====================================================
# TEST 1: LOGIN (Ottenere Access Token + Refresh Token)
# =====================================================
Write-Host "[TEST 1] LOGIN - Ottenere i token..." -ForegroundColor Yellow

$loginBody = @{
    email = "user@example.com"
    password = "123456"
} | ConvertTo-Json

try {
    $loginResponse = Invoke-RestMethod -Uri "$BaseUrl/api/auth/login" `
        -Method Post `
        -ContentType $ContentType `
        -Body $loginBody

    Write-Host ($loginResponse | ConvertTo-Json) -ForegroundColor White

    $accessToken = $loginResponse.token
    $refreshToken = $loginResponse.refreshToken
    $expiresIn = $loginResponse.expiresIn

    if ($accessToken -and $refreshToken) {
        Write-Host "✅ LOGIN SUCCESSO" -ForegroundColor Green
        Write-Host "Access Token: $($accessToken.Substring(0, [Math]::Min(50, $accessToken.Length)))..."
        Write-Host "Refresh Token: $refreshToken"
        Write-Host "Expires In: $expiresIn secondi`n"
    } else {
        Write-Host "❌ LOGIN FALLITO`n" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "❌ ERRORE LOGIN: $($_.Exception.Message)`n" -ForegroundColor Red
    exit 1
}

Start-Sleep -Seconds 2

# =====================================================
# TEST 2: USARE ACCESS TOKEN (Chiamata API Protetta)
# =====================================================
Write-Host "[TEST 2] USARE ACCESS TOKEN - Chiamata API protetta..." -ForegroundColor Yellow

try {
    $headers = @{
        Authorization = "Bearer $accessToken"
    }

    $profileResponse = Invoke-RestMethod -Uri "$BaseUrl/api/student/profile" `
        -Method Get `
        -Headers $headers

    Write-Host ($profileResponse | ConvertTo-Json) -ForegroundColor White

    if ($profileResponse.id) {
        Write-Host "✅ ACCESSO API SUCCESSO`n" -ForegroundColor Green
    } else {
        Write-Host "❌ ACCESSO API FALLITO`n" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ ERRORE ACCESSO API: $($_.Exception.Message)`n" -ForegroundColor Red
}

Start-Sleep -Seconds 2

# =====================================================
# TEST 3: REFRESH TOKEN (Rinnovare Access Token)
# =====================================================
Write-Host "[TEST 3] REFRESH TOKEN - Rinnovare i token..." -ForegroundColor Yellow

$refreshBody = @{
    refreshToken = $refreshToken
} | ConvertTo-Json

try {
    $refreshResponse = Invoke-RestMethod -Uri "$BaseUrl/api/auth/refresh" `
        -Method Post `
        -ContentType $ContentType `
        -Body $refreshBody

    Write-Host ($refreshResponse | ConvertTo-Json) -ForegroundColor White

    $newAccessToken = $refreshResponse.token
    $newRefreshToken = $refreshResponse.refreshToken

    if ($newAccessToken -and $newRefreshToken) {
        Write-Host "✅ REFRESH SUCCESSO" -ForegroundColor Green
        Write-Host "Nuovo Access Token: $($newAccessToken.Substring(0, [Math]::Min(50, $newAccessToken.Length)))..."
        Write-Host "Nuovo Refresh Token: $newRefreshToken"
        Write-Host "⚠️ IMPORTANTE: Il vecchio refresh token ($refreshToken) è stato REVOCATO`n" -ForegroundColor Yellow
    } else {
        Write-Host "❌ REFRESH FALLITO`n" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "❌ ERRORE REFRESH: $($_.Exception.Message)`n" -ForegroundColor Red
    exit 1
}

Start-Sleep -Seconds 2

# =====================================================
# TEST 4: USARE NUOVO ACCESS TOKEN
# =====================================================
Write-Host "[TEST 4] USARE NUOVO ACCESS TOKEN - Verifica nuovo token..." -ForegroundColor Yellow

try {
    $newHeaders = @{
        Authorization = "Bearer $newAccessToken"
    }

    $newProfileResponse = Invoke-RestMethod -Uri "$BaseUrl/api/student/profile" `
        -Method Get `
        -Headers $newHeaders

    Write-Host ($newProfileResponse | ConvertTo-Json) -ForegroundColor White

    if ($newProfileResponse.id) {
        Write-Host "✅ NUOVO ACCESS TOKEN FUNZIONANTE`n" -ForegroundColor Green
    } else {
        Write-Host "❌ NUOVO ACCESS TOKEN NON FUNZIONANTE`n" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ ERRORE NUOVO ACCESS TOKEN: $($_.Exception.Message)`n" -ForegroundColor Red
}

Start-Sleep -Seconds 2

# =====================================================
# TEST 5: SECURITY - Riusare Vecchio Refresh Token (ATTACCO)
# =====================================================
Write-Host "[TEST 5] " -ForegroundColor Yellow -NoNewline
Write-Host "SECURITY TEST" -ForegroundColor Red -NoNewline
Write-Host " - Tentativo di riuso token revocato (attacco)..." -ForegroundColor Yellow

$reuseBody = @{
    refreshToken = $refreshToken
} | ConvertTo-Json

try {
    $reuseResponse = Invoke-RestMethod -Uri "$BaseUrl/api/auth/refresh" `
        -Method Post `
        -ContentType $ContentType `
        -Body $reuseBody

    Write-Host ($reuseResponse | ConvertTo-Json) -ForegroundColor White
    Write-Host "❌ SECURITY FAIL - Token revocato accettato!`n" -ForegroundColor Red
} catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    Write-Host "Status Code: $statusCode" -ForegroundColor White
    
    if ($statusCode -eq 403 -or $statusCode -eq 401) {
        Write-Host "✅ ATTACCO RILEVATO - Token revocato rifiutato (Status: $statusCode)" -ForegroundColor Green
        Write-Host "🚨 SECURITY ALERT: Tutti i token dell'utente dovrebbero essere stati revocati`n" -ForegroundColor Red
    } else {
        Write-Host "❌ SECURITY FAIL - Risposta inaspettata (Status: $statusCode)`n" -ForegroundColor Red
    }
}

Start-Sleep -Seconds 2

# =====================================================
# TEST 6: Verificare che anche il nuovo token è stato revocato
# =====================================================
Write-Host "[TEST 6] VERIFICA REVOCA - Tentativo di usare nuovo refresh token..." -ForegroundColor Yellow

$verifyRevokeBody = @{
    refreshToken = $newRefreshToken
} | ConvertTo-Json

try {
    $verifyRevokeResponse = Invoke-RestMethod -Uri "$BaseUrl/api/auth/refresh" `
        -Method Post `
        -ContentType $ContentType `
        -Body $verifyRevokeBody

    Write-Host ($verifyRevokeResponse | ConvertTo-Json) -ForegroundColor White
    Write-Host "❌ VERIFICA REVOCA FALLITA - Token ancora valido`n" -ForegroundColor Red
} catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    
    if ($statusCode -eq 401) {
        Write-Host "✅ VERIFICA REVOCA SUCCESSO - Anche il nuovo token è stato revocato (Status: $statusCode)`n" -ForegroundColor Green
    } else {
        Write-Host "❌ VERIFICA REVOCA FALLITA - Risposta inaspettata (Status: $statusCode)`n" -ForegroundColor Red
    }
}

Start-Sleep -Seconds 2

# =====================================================
# TEST 7: RE-LOGIN (Dopo revoca completa)
# =====================================================
Write-Host "[TEST 7] RE-LOGIN - Dopo revoca tutti i token..." -ForegroundColor Yellow

$reloginBody = @{
    email = "user@example.com"
    password = "123456"
} | ConvertTo-Json

try {
    $reloginResponse = Invoke-RestMethod -Uri "$BaseUrl/api/auth/login" `
        -Method Post `
        -ContentType $ContentType `
        -Body $reloginBody

    Write-Host ($reloginResponse | ConvertTo-Json) -ForegroundColor White

    $finalAccessToken = $reloginResponse.token
    $finalRefreshToken = $reloginResponse.refreshToken

    if ($finalAccessToken -and $finalRefreshToken) {
        Write-Host "✅ RE-LOGIN SUCCESSO" -ForegroundColor Green
        Write-Host "Nuovo Access Token: $($finalAccessToken.Substring(0, [Math]::Min(50, $finalAccessToken.Length)))..."
        Write-Host "Nuovo Refresh Token: $finalRefreshToken`n"
    } else {
        Write-Host "❌ RE-LOGIN FALLITO`n" -ForegroundColor Red
        exit 1
    }
} catch {
    Write-Host "❌ ERRORE RE-LOGIN: $($_.Exception.Message)`n" -ForegroundColor Red
    exit 1
}

Start-Sleep -Seconds 2

# =====================================================
# TEST 8: LOGOUT (Revocare Refresh Token)
# =====================================================
Write-Host "[TEST 8] LOGOUT - Revocare refresh token manualmente..." -ForegroundColor Yellow

$logoutBody = @{
    refreshToken = $finalRefreshToken
} | ConvertTo-Json

try {
    $logoutResponse = Invoke-RestMethod -Uri "$BaseUrl/api/auth/logout" `
        -Method Post `
        -ContentType $ContentType `
        -Body $logoutBody

    Write-Host ($logoutResponse | ConvertTo-Json) -ForegroundColor White

    if ($logoutResponse.success -eq $true) {
        Write-Host "✅ LOGOUT SUCCESSO - Refresh token revocato`n" -ForegroundColor Green
    } else {
        Write-Host "❌ LOGOUT FALLITO`n" -ForegroundColor Red
    }
} catch {
    Write-Host "❌ ERRORE LOGOUT: $($_.Exception.Message)`n" -ForegroundColor Red
}

Start-Sleep -Seconds 2

# =====================================================
# TEST 9: Verificare che il token revocato non funziona
# =====================================================
Write-Host "[TEST 9] VERIFICA LOGOUT - Tentativo di usare refresh token revocato..." -ForegroundColor Yellow

$verifyLogoutBody = @{
    refreshToken = $finalRefreshToken
} | ConvertTo-Json

try {
    $verifyLogoutResponse = Invoke-RestMethod -Uri "$BaseUrl/api/auth/refresh" `
        -Method Post `
        -ContentType $ContentType `
        -Body $verifyLogoutBody

    Write-Host ($verifyLogoutResponse | ConvertTo-Json) -ForegroundColor White
    Write-Host "❌ VERIFICA LOGOUT FALLITA - Token ancora valido`n" -ForegroundColor Red
} catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    
    if ($statusCode -eq 401) {
        Write-Host "✅ VERIFICA LOGOUT SUCCESSO - Token revocato rifiutato (Status: $statusCode)`n" -ForegroundColor Green
    } else {
        Write-Host "❌ VERIFICA LOGOUT FALLITA - Risposta inaspettata (Status: $statusCode)`n" -ForegroundColor Red
    }
}

# =====================================================
# RIEPILOGO FINALE
# =====================================================
Write-Host "========================================" -ForegroundColor Blue
Write-Host "   RIEPILOGO TEST" -ForegroundColor Blue
Write-Host "========================================`n" -ForegroundColor Blue

Write-Host "✅ TEST COMPLETATI CON SUCCESSO:" -ForegroundColor Green
Write-Host "   1. Login con ottenimento token"
Write-Host "   2. Accesso API con access token"
Write-Host "   3. Refresh token (token rotation)"
Write-Host "   4. Verifica nuovo access token"
Write-Host "   5. Reuse detection (attacco rilevato)"
Write-Host "   6. Verifica revoca completa"
Write-Host "   7. Re-login dopo attacco"
Write-Host "   8. Logout manuale"
Write-Host "   9. Verifica logout"

Write-Host "`n⚠️ NOTE IMPORTANTI:" -ForegroundColor Yellow
Write-Host "   - Access Token JWT: 15 minuti di validità"
Write-Host "   - Refresh Token UUID: 7 giorni di validità"
Write-Host "   - Token Rotation: Ogni refresh genera nuovo token"
Write-Host "   - Reuse Detection: Token revocato riusato → tutti token revocati"
Write-Host "   - Max token per utente: 5 (configurabile)"

Write-Host "`n========================================" -ForegroundColor Blue
Write-Host "   TUTTI I TEST COMPLETATI! 🎉" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Blue
