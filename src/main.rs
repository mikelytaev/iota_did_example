use identity_iota::core::json;
use identity_iota::core::FromJson;
use identity_iota::client::ExplorerUrl;
use identity_iota::iota_core::IotaService;
use identity_iota::iota_core::IotaVerificationMethod;
use identity_iota::did::MethodScope;
use identity_iota::did::DID;
use identity_iota::did::Service;
use identity_iota::prelude::*;


#[allow(dead_code)]
#[tokio::main]
async fn main() -> Result<()> {

    // Генерируем пару публичного и приватного ключа по схеме Ed25519
    let keypair: KeyPair = KeyPair::new(KeyType::Ed25519)?;

    // Создаем DID и DID Document по методу IOTA DID Method
    let mut document: IotaDocument = IotaDocument::new(&keypair)?;

    // Добавляем в DIDDoc способ связи с нами - в данном случае веб сайт
    let service: IotaService = Service::from_json_value(json!({
    "id": document.id().to_url().join("#myWebsite")?,
    "type": "LinkedDomains",
    "serviceEndpoint": "https://habr.com"
    }))?;
    document.insert_service(service);

    // Создадим еще одну пару ключей, ассоциированную с этим DID
    let new_key: KeyPair = KeyPair::new(KeyType::Ed25519)?;
    let method: IotaVerificationMethod =
        IotaVerificationMethod::new(document.id().clone(), new_key.type_(), new_key.public(), "newKey")?;
    assert!(document.insert_method(method, MethodScope::VerificationMethod).is_ok());

    // Подписываем наш DIDDoc приватным ключом
    document.sign_self(keypair.private(), document.default_signing_method()?.id().clone())?;

    // Так выглядит наш DIDDoc
    println!("DID Document JSON > {:#}", document.core_document());

    // Создаем экземпляр клиента для отправки в сеть IOTA
    let client: Client = Client::new().await?;

    // Публикуем DIDDoc в сети IOTA
    client.publish_document(&document).await?;

    // Наш только что созданный и опубликованный DIDDoc можно увидеть в обозревателе сети IOTA
    let explorer: &ExplorerUrl = ExplorerUrl::mainnet();
    println!("Explore the DID Document > {}", explorer.resolver_url(document.id())?);

    Ok(())
}