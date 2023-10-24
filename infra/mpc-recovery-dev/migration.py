from google.oauth2 import service_account
from google.cloud import datastore

credentials_source = service_account.Credentials.from_service_account_file(
    '../source-service-keys.json')
client_source = datastore.Client(project="pagoda-discovery-platform-dev", credentials=credentials_source)

credentials_target = service_account.Credentials.from_service_account_file(
    '../target-service-keys.json')
client_target = datastore.Client(project="pagoda-discovery-platform-prod", credentials=credentials_target)

print('Fetching source entities')
query = credentials_source.query(kind="EncryptedUserCredentials-dev")
entities = []
for entity in list(query.fetch()):
    entity.key = client_target.key('EncryptedUserCredentials-mainnet').completed_key(entity.key.id_or_name)
    print(entity.key)
    print(entity)
    entities.append(entity)

print("Uploading a total of " + str(len(entities)) + " entities to target")
client_target.put_multi(entities)