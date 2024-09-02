set -ux

export KCADM_CONFIG_FILE=/tmp/kcadm.conf
export KEYCLOAK_API_URL='http://keycloak:8080'
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD=admin
export MY_REALM_NAME=my-realm
export MY_REALM_DISPLAY_NAME="My Realm"

MY_APP_CLIENT_ID="my-app"
MY_APP_CLIENT_SECRET="${MY_APP_CLIENT_ID}"
MY_APP_CLIENT_NAME="My App"
MY_APP_URL=http://localhost:8080

function login_to_keycloak_api() {
  kcadm.sh config credentials \
    --config ${KCADM_CONFIG_FILE} \
    --server ${KEYCLOAK_API_URL} \
    --realm master \
    --user ${ADMIN_USERNAME} \
    --password ${ADMIN_PASSWORD}
}

login_to_keycloak_api

function realm_exists() {
  local realm_name="$1"

  kcadm.sh get realms/"${realm_name}" \
    --config "${KCADM_CONFIG_FILE}" 2>&1 \
      | grep "Resource not found for url: ${KEYCLOAK_API_URL}/admin/realms/${realm_name}"
}

function set_up_my_realm() {
  args=(
    --config "${KCADM_CONFIG_FILE}"
    --set realm="${MY_REALM_NAME}"
    --set displayName="${MY_REALM_DISPLAY_NAME}"
    --set enabled=true
  )

  kcadm.sh create realms \
    "${args[@]}"  || :
}

set_up_my_realm

function set_up_my_app_client() {
  local realm_name="$1"

  args=(
    --config "${KCADM_CONFIG_FILE}"
    --target-realm "${realm_name}"
    --set clientId="${MY_APP_CLIENT_ID}"
    --set secret="${MY_APP_CLIENT_SECRET}"
    --set name="${MY_APP_CLIENT_NAME}"
    --set publicClient=false
    --set serviceAccountsEnabled=true
    --set baseUrl="${MY_APP_URL}"
    --set 'redirectUris=["'"${MY_APP_URL}"'/*"]'
    --set 'webOrigins=["'"${MY_APP_URL}"'/"]'
  )
  kcadm.sh create clients \
    "${args[@]}" || :
}

set_up_my_app_client ${MY_REALM_NAME}

function set_up_users() {
  local realm_name="$1"

  kcadm.sh create partialImport \
    --config ${KCADM_CONFIG_FILE} \
    --target-realm "${realm_name}" \
    --set ifResourceExists=OVERWRITE \
    --file keycloak-users.json
}

set_up_users ${MY_REALM_NAME}
