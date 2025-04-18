#!/bin/bash
# scripts/setup-keycloak.sh

# Definiere Variablen
KEYCLOAK_URL=""
REALM_NAME=""
ADMIN_USER=""
ADMIN_PASSWORD=""
CLIENT_ID=""
CLIENT_SECRET=""

# Farben für Terminal-Ausgabe
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Funktion zum Anzeigen von Nachrichten
function log() {
  echo -e "${GREEN}[INFO]${NC} $1"
}

function warn() {
  echo -e "${YELLOW}[WARN]${NC} $1"
}

function error() {
  echo -e "${RED}[ERROR]${NC} $1"
}

# Funktion zum Überprüfen, ob ein Befehl existiert
function command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Prüfe, ob curl installiert ist
if ! command_exists curl; then
  error "curl ist nicht installiert. Bitte installieren Sie curl und versuchen Sie es erneut."
  exit 1
fi

# Prüfe, ob jq installiert ist
if ! command_exists jq; then
  error "jq ist nicht installiert. Bitte installieren Sie jq und versuchen Sie es erneut."
  exit 1
fi

log "Starte Keycloak-Setup für Realm '$REALM_NAME'..."

# Hole Admin-Token
log "Hole Admin-Token..."
ADMIN_TOKEN=$(curl -s -X POST "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=$ADMIN_USER" \
  -d "password=$ADMIN_PASSWORD" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" | jq -r '.access_token')

if [ -z "$ADMIN_TOKEN" ] || [ "$ADMIN_TOKEN" == "null" ]; then
  error "Konnte kein Admin-Token abrufen. Bitte überprüfen Sie die Anmeldedaten und stellen Sie sicher, dass Keycloak läuft."
  exit 1
fi

log "Admin-Token erfolgreich abgerufen."

# Prüfe, ob Realm bereits existiert
REALM_EXISTS=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[] | select(.realm=="'$REALM_NAME'") | .realm')

# Erstelle Realm, wenn er nicht existiert
if [ -z "$REALM_EXISTS" ]; then
  log "Erstelle neuen Realm '$REALM_NAME'..."
  
  curl -s -X POST "$KEYCLOAK_URL/admin/realms" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "realm": "'$REALM_NAME'",
      "enabled": true,
      "displayName": "officemadeeasy",
      "accessTokenLifespan": 300,
      "ssoSessionIdleTimeout": 1800,
      "ssoSessionMaxLifespan": 36000,
      "offlineSessionIdleTimeout": 2592000,
      "accessCodeLifespan": 60,
      "accessCodeLifespanUserAction": 300,
      "accessCodeLifespanLogin": 1800,
      "bruteForceProtected": true,
      "resetPasswordAllowed": true,
      "verifyEmail": false,
      "loginWithEmailAllowed": true,
      "duplicateEmailsAllowed": false,
      "permanentLockout": false,
      "maxFailureWaitSeconds": 900,
      "minimumQuickLoginWaitSeconds": 60,
      "waitIncrementSeconds": 60,
      "quickLoginCheckMilliSeconds": 1000,
      "maxDeltaTimeSeconds": 43200,
      "failureFactor": 5
    }'
  
  if [ $? -ne 0 ]; then
    error "Fehler beim Erstellen des Realms '$REALM_NAME'."
    exit 1
  fi
  
  log "Realm '$REALM_NAME' erfolgreich erstellt."
else
  log "Realm '$REALM_NAME' existiert bereits."
fi

# Erstelle Client, wenn er nicht existiert
log "Prüfe, ob Client '$CLIENT_ID' bereits existiert..."

CLIENT_EXISTS=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[] | select(.clientId=="'$CLIENT_ID'") | .clientId')

if [ -z "$CLIENT_EXISTS" ]; then
  log "Erstelle neuen Client '$CLIENT_ID'..."
  
  curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "clientId": "'$CLIENT_ID'",
      "name": "Multi-Tenant API",
      "description": "Client für den Zugriff auf die Multi-Tenant API",
      "enabled": true,
      "clientAuthenticatorType": "client-secret",
      "secret": "'$CLIENT_SECRET'",
      "redirectUris": [
        "http://localhost:3000/*",
        "http://localhost:5000/*"
      ],
      "webOrigins": [
        "http://localhost:3000",
        "http://localhost:5000"
      ],
      "publicClient": false,
      "protocol": "openid-connect",
      "bearerOnly": false,
      "standardFlowEnabled": true,
      "implicitFlowEnabled": true,
      "directAccessGrantsEnabled": true,
      "serviceAccountsEnabled": true,
      "authorizationServicesEnabled": true
    }'
  
  if [ $? -ne 0 ]; then
    error "Fehler beim Erstellen des Clients '$CLIENT_ID'."
    exit 1
  fi
  
  log "Client '$CLIENT_ID' erfolgreich erstellt."
else
  log "Client '$CLIENT_ID' existiert bereits."
fi

# Hole Client-ID
CLIENT_UUID=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[] | select(.clientId=="'$CLIENT_ID'") | .id')

if [ -z "$CLIENT_UUID" ]; then
  error "Konnte Client-UUID nicht abrufen."
  exit 1
fi

# Hole oder generiere Client-Secret
CLIENT_SECRET_JSON=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients/$CLIENT_UUID/client-secret" \
  -H "Authorization: Bearer $ADMIN_TOKEN")

CLIENT_SECRET=$(echo $CLIENT_SECRET_JSON | jq -r '.value')

if [ -z "$CLIENT_SECRET" ] || [ "$CLIENT_SECRET" == "null" ]; then
  log "Generiere neues Client-Secret..."
  
  REGENERATE_RESPONSE=$(curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients/$CLIENT_UUID/client-secret" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
  
  CLIENT_SECRET_JSON=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM_NAME/clients/$CLIENT_UUID/client-secret" \
    -H "Authorization: Bearer $ADMIN_TOKEN")
  
  CLIENT_SECRET=$(echo $CLIENT_SECRET_JSON | jq -r '.value')
  
  if [ -z "$CLIENT_SECRET" ] || [ "$CLIENT_SECRET" == "null" ]; then
    error "Konnte Client-Secret nicht generieren."
    exit 1
  fi
fi

log "Client-Secret: $CLIENT_SECRET"

# Erstelle alle benötigten Rollen
ROLES=("OmeAdmin" "OmeDeputyAdmin" "OmeOfficeWorker" "OmeSuperUser" "OmeTechUser" "OmeTechnician" "OmeTechnicianManager" "OmeTrainee")

for ROLE in "${ROLES[@]}"; do
  log "Prüfe, ob Rolle '$ROLE' bereits existiert..."
  
  ROLE_EXISTS=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[] | select(.name=="'$ROLE'") | .name')
  
  if [ -z "$ROLE_EXISTS" ]; then
    log "Erstelle neue Rolle '$ROLE'..."
    
    curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles" \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      -d '{
        "name": "'$ROLE'",
        "description": "Rolle für '$ROLE'",
        "composite": false,
        "clientRole": false
      }'
    
    if [ $? -ne 0 ]; then
      warn "Fehler beim Erstellen der Rolle '$ROLE'."
    else
      log "Rolle '$ROLE' erfolgreich erstellt."
    fi
  else
    log "Rolle '$ROLE' existiert bereits."
  fi
done

# Erstelle Beispiel-Tenants
TENANTS=("hergers-brandschutz")

for TENANT in "${TENANTS[@]}"; do
  log "Prüfe, ob Gruppe '$TENANT' bereits existiert..."
  
  GROUP_EXISTS=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM_NAME/groups" \
    -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[] | select(.name=="'$TENANT'") | .name')
  
  if [ -z "$GROUP_EXISTS" ]; then
    log "Erstelle neue Gruppe '$TENANT'..."
    
    TENANT_ID=$(uuidgen)
    
    curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/groups" \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      -d '{
        "name": "'$TENANT'",
        "attributes": {
          "tenant_id": ["'$TENANT_ID'"]
        }
      }'
    
    if [ $? -ne 0 ]; then
      warn "Fehler beim Erstellen der Gruppe '$TENANT'."
    else
      log "Gruppe '$TENANT' erfolgreich erstellt mit tenant_id: $TENANT_ID."
    fi
  else
    log "Gruppe '$TENANT' existiert bereits."
  fi
done

# Erstelle Admin-Benutzer
log "Erstelle Admin-Benutzer..."

ADMIN_USERNAME="vcaricato"
ADMIN_PASSWORD="Test1234"
ADMIN_EMAIL="info@officemadeeasy.eu"

USER_EXISTS=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users?username=$ADMIN_USERNAME" \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].username')

if [ -z "$USER_EXISTS" ] || [ "$USER_EXISTS" == "null" ]; then
  log "Erstelle neuen Admin-Benutzer '$ADMIN_USERNAME'..."
  
  USER_ID=$(curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{
      "username": "'$ADMIN_USERNAME'",
      "email": "'$ADMIN_EMAIL'",
      "enabled": true,
      "emailVerified": true,
      "firstName": "Admin",
      "lastName": "User",
      "credentials": [
        {
          "type": "password",
          "value": "'$ADMIN_PASSWORD'",
          "temporary": false
        }
      ]
    }' --write-out '%{http_code}' --output /dev/null)
  
  if [ "$USER_ID" -ne 201 ]; then
    error "Fehler beim Erstellen des Admin-Benutzers. HTTP-Status: $USER_ID"
  else
    log "Admin-Benutzer '$ADMIN_USERNAME' erfolgreich erstellt."
    
    # Hole die Benutzer-ID
    USER_ID=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users?username=$ADMIN_USERNAME" \
      -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[0].id')
    
    # Füge Admin-Rolle hinzu
    ADMIN_ROLE_ID=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM_NAME/roles" \
      -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[] | select(.name=="OmeAdmin") | .id')
    
    if [ -n "$ADMIN_ROLE_ID" ] && [ "$ADMIN_ROLE_ID" != "null" ]; then
      curl -s -X POST "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users/$USER_ID/role-mappings/realm" \
        -H "Authorization: Bearer $ADMIN_TOKEN" \
        -H "Content-Type: application/json" \
        -d '[{
          "id": "'$ADMIN_ROLE_ID'",
          "name": "OmeAdmin"
        }]'
      
      log "Admin-Rolle 'OmeAdmin' dem Benutzer hinzugefügt."
    fi
    
    # Füge Benutzer zur ersten Tenant-Gruppe hinzu
    TENANT_GROUP_ID=$(curl -s -X GET "$KEYCLOAK_URL/admin/realms/$REALM_NAME/groups" \
      -H "Authorization: Bearer $ADMIN_TOKEN" | jq -r '.[] | select(.name=="hergers-brandschutz") | .id')
    
    if [ -n "$TENANT_GROUP_ID" ] && [ "$TENANT_GROUP_ID" != "null" ]; then
      curl -s -X PUT "$KEYCLOAK_URL/admin/realms/$REALM_NAME/users/$USER_ID/groups/$TENANT_GROUP_ID" \
        -H "Authorization: Bearer $ADMIN_TOKEN"
      
      log "Benutzer zur Gruppe 'hergers-brandschutz' hinzugefügt."
    fi
  fi
else
  log "Admin-Benutzer '$ADMIN_USERNAME' existiert bereits."
fi

log "Keycloak-Setup abgeschlossen."
log "Sie können sich nun mit folgenden Anmeldedaten anmelden:"
log "Username: $ADMIN_USERNAME"
log "Password: $ADMIN_PASSWORD"
log "Realm: $REALM_NAME"
log "Client ID: $CLIENT_ID"
log "Client Secret: $CLIENT_SECRET"