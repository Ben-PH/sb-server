use std::num::NonZeroU32;

use actix_files::{Files, NamedFile};
use actix_identity::Identity;
use actix_web::{post, web, App, HttpResponse, HttpServer, Result, Responder};
use actix_web::{post, web, App, HttpResponse, HttpServer, Result, Responder, middleware};
use rand::Rng;

use mongodb::bson::{ self, doc, Binary, spec};
use serde::{Serialize, Deserialize};

static PBKDF2_ALG: ring::pbkdf2::Algorithm = ring::pbkdf2::PBKDF2_HMAC_SHA256;
const CREDENTIAL_LEN: usize = ring::digest::SHA256_OUTPUT_LEN;
#[derive(Serialize)]
pub struct Credential([u8; CREDENTIAL_LEN]);
static PWD_DB_SALT: &[u8; 16] = b"database spicey!";

struct DbCollections {
    users: mongodb::Collection,
}

struct PwdDb {
    pbkdf2_iters: NonZeroU32,
    db_salt: &'static [u8; 16],
    storage: mongodb::Collection,
}

#[derive(Serialize, Deserialize)]
struct AuthData {
    email: String,
    password: String,
}


#[derive(Serialize, Deserialize)]
struct UserDocument {
    _id: bson::oid::ObjectId,
    first_name: String,
    last_name: String,
    email: String,
    password: String,
}

#[derive(Serialize, Deserialize)]
struct User {
    first_name: String,
    last_name: String,
    email: String,
    password: String,
}

async fn index(id: Identity) -> Result<NamedFile> {
    println!("your id is {:?}", id.identity());
    Ok(NamedFile::open("./client/index.html")?)
}

impl PwdDb {
    fn entry_salt(&self, user_salt_comp: &str) -> Vec<u8> {
        let mut salt = Vec::with_capacity(self.db_salt.len() +
                                          user_salt_comp.as_bytes().len());
        salt.extend(self.db_salt.as_ref());
        salt.extend(user_salt_comp.as_bytes());
        salt
    }
}

#[post("/create")]
async fn create(
    auth_data: web::Json<User>,
    user_db: web::Data<DbCollections>,
    pswd_db: web::Data<PwdDb>,
) -> Result<impl Responder> {
    let user_db = user_db.into_inner();
    let auth_data = auth_data.into_inner();
    if let Ok(Some(_)) = user_db.users.find_one(doc!{"email": &auth_data.email}, None).await {
        return HttpResponse::Unauthorized().reason("user already exists").await
    }

    let pswd_db = pswd_db.into_inner();
    if let Ok(Some(_)) = pswd_db.storage.find_one(doc!{"email": &auth_data.email}, None).await {
        return HttpResponse::InternalServerError().reason("inconsistent database").await
    }
    let salt = pswd_db.entry_salt(&auth_data.email);
    let mut to_store = Credential([0u8; CREDENTIAL_LEN]);
    ring::pbkdf2::derive(PBKDF2_ALG, pswd_db.pbkdf2_iters, &salt,
                          &auth_data.password.as_bytes(), &mut to_store.0);
    let hash = Binary{
                    subtype: spec::BinarySubtype::Generic,
                    bytes: to_store.0.to_vec()
    };
    let foo = pswd_db
        .storage
        .insert_one(
            doc!{
                "email": &auth_data.email,
                "hashed": &hash,
            },
            None
        ).await;

    let bar = user_db
        .users
        .insert_one(
            doc!{
                "first_name": auth_data.first_name,
                "last_name": auth_data.last_name,
                "email": auth_data.email,
                // TODO: link to password hashing document
                "password": &hash,
            },
            None
        ).await;
    HttpResponse::Ok().await
}


#[post("/login")]
async fn login(
    auth_data: web::Json<AuthData>,
    col: web::Data<DbCollections>
) -> Result<impl Responder> {

    let auth = auth_data.into_inner();
    let doc = col.users.find_one(doc!{"email": &auth.email, "password": &auth.password}, None).await;
    // if doc.is_ok() {id.remember(auth.email);}
    if doc.is_ok() {
        HttpResponse::Ok().await
    } else {
        HttpResponse::Unauthorized().await
    }
}

#[post("/logout/{name}")]
async fn logout(id: Identity, name: web::Path<String>) -> Result<impl Responder> {

    match id.identity() {
        Some(name) => {
            println!("goodbye, {:?}", name);
            id.forget();
            HttpResponse::Ok().finish().await
        },
        None => {
            println!("you say you are {:?}, but I don't think we've met :(", name);
            HttpResponse::Ok().finish().await
        }

    }

}
#[actix_rt::main]
async fn main() -> std::io::Result<()> {

    std::env::set_var("RUST_LOG", "actix_web=info");
    env_logger::init();
    let db = mongodb::Client::with_uri_str("mongodb://localhost:27017")
        .await.unwrap().database("spacebook");

    HttpServer::new(move || {
        let users = db.collection("users");
        let pwds = db.collection("passwords");

        App::new()
            .wrap(middleware::Logger::default())
            .data(DbCollections{users})
            .data(PwdDb{pbkdf2_iters: NonZeroU32::new(1000).unwrap(), db_salt: PWD_DB_SALT, storage: pwds})
            .service(
                web::scope("/api/auth")
                    .service(create)
                    .service(login)
                    .service(logout)
                    .service(Files::new("/pkg", "./client/pkg"))
                    .default_service(web::route().to(web::HttpResponse::NotFound)),
            )
            .service(Files::new("/pkg", "./client/pkg"))
            .default_service(web::get().to(index))
    })
        .bind("127.0.0.1:8080")?
    .run()
    .await
}
